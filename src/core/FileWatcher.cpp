/*
 *  Copyright (C) 2020 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "FileWatcher.h"

#include "core/AsyncTask.h"

#ifdef Q_OS_LINUX
#include <sys/statfs.h>
#endif

FileWatcher::FileWatcher(QObject* parent)
    : QObject(parent)
{
    connect(&m_fileWatcher, SIGNAL(fileChanged(QString)), SLOT(checkFileChanged()));
    connect(&m_fileChecksumTimer, SIGNAL(timeout()), SLOT(checkFileChanged()));
    connect(&m_fileChangeDelayTimer, &QTimer::timeout, this, [this] { emit fileChanged(m_filePath); });
    m_fileChangeDelayTimer.setSingleShot(true);
    m_fileIgnoreDelayTimer.setSingleShot(true);
}

FileWatcher::~FileWatcher()
{
    stop();
}

void FileWatcher::start(const QString& filePath, int checksumIntervalSeconds, int checksumSizeKibibytes)
{
    stop();

#if defined(Q_OS_LINUX)
    struct statfs statfsBuf;
    bool forcePolling = false;
    const auto NFS_SUPER_MAGIC = 0x6969;

    if (!statfs(filePath.toLocal8Bit().constData(), &statfsBuf)) {
        forcePolling = (statfsBuf.f_type == NFS_SUPER_MAGIC);
    } else {
        // if we can't get the fs type let's fall back to polling
        forcePolling = true;
    }
    auto objectName = forcePolling ? QLatin1String("_qt_autotest_force_engine_poller") : QLatin1String("");
    m_fileWatcher.setObjectName(objectName);
#endif

    m_fileWatcher.addPath(filePath);
    m_filePath = filePath;

    // Handle file checksum
    m_fileChecksumSizeBytes = checksumSizeKibibytes * 1024;
    m_fileChecksum = calculateChecksum(m_filePath, m_fileChecksumSizeBytes);
    if (checksumIntervalSeconds > 0) {
        m_fileChecksumTimer.start(checksumIntervalSeconds * 1000);
    }
}

void FileWatcher::stop()
{
    ++m_watchGeneration;
    m_checksumPending = false;
    if (!m_filePath.isEmpty()) {
        m_fileWatcher.removePath(m_filePath);
    }
    m_filePath.clear();
    m_fileChecksum.clear();
    m_fileChecksumTimer.stop();
    m_fileChangeDelayTimer.stop();
    m_fileIgnoreDelayTimer.stop();
    m_paused = false;
}

void FileWatcher::pause()
{
    m_paused = true;
    m_fileChangeDelayTimer.stop();
}

void FileWatcher::resume()
{
    m_paused = false;
    // Add a short delay to start in the next event loop
    if (!m_fileIgnoreDelayTimer.isActive()) {
        m_fileIgnoreDelayTimer.start(0);
    }
}

bool FileWatcher::shouldIgnoreChanges()
{
    return m_filePath.isEmpty() || m_checksumPending || m_paused || m_fileIgnoreDelayTimer.isActive()
           || m_fileChangeDelayTimer.isActive();
}

bool FileWatcher::hasSameFileChecksum()
{
    const auto checksum = calculateChecksum(m_filePath, m_fileChecksumSizeBytes);
    return checksum.isEmpty() || checksum == m_fileChecksum;
}

void FileWatcher::checkFileChanged()
{
    if (shouldIgnoreChanges()) {
        return;
    }

    m_checksumPending = true;
    // A slow filesystem read can outlive this watch or the watcher itself.
    AsyncTask::runThenCallback(
        [path = m_filePath, sizeBytes = m_fileChecksumSizeBytes] { return calculateChecksum(path, sizeBytes); },
        this,
        [this, generation = m_watchGeneration](const QByteArray& checksum) {
            if (generation != m_watchGeneration) {
                return;
            }

            m_checksumPending = false;
            if (!m_paused && !checksum.isEmpty() && checksum != m_fileChecksum) {
                m_fileChecksum = checksum;
                m_fileChangeDelayTimer.start(0);
            }
        });
}

QByteArray FileWatcher::calculateChecksum(const QString& path, int sizeBytes)
{
    QFile file(path);
    if (path.isEmpty() || !file.open(QFile::ReadOnly)) {
        return {};
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (sizeBytes > 0) {
        hash.addData(file.read(sizeBytes));
    } else if (!hash.addData(&file)) {
        return {};
    }
    return file.error() == QFileDevice::NoError ? hash.result() : QByteArray{};
}
