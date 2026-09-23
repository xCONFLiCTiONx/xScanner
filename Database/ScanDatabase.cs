using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Data.Sqlite;
using xScanner.Database.Models;

namespace xScanner.Database
{
    public class ScanDatabase
    {
        private readonly string _connectionString;
        private readonly string _dbPath;

        public ScanDatabase(string dbPath = "")
        {
            if (string.IsNullOrEmpty(dbPath))
            {
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                var dir = Path.Combine(appData, "xScanner");
                Directory.CreateDirectory(dir);
                _dbPath = Path.Combine(dir, "xscanner.db");
            }
            else
            {
                _dbPath = dbPath;
            }

            _connectionString = $"Data Source={_dbPath}";
            InitializeDatabase();
        }

        private void InitializeDatabase()
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            string createFilesTable = @"
                CREATE TABLE IF NOT EXISTS Files (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    FilePath TEXT UNIQUE,
                    FileSize INTEGER,
                    LastModified TEXT,
                    Sha256 TEXT,
                    LastScanTime TEXT,
                    ScanResult TEXT,
                    DefinitionVersion TEXT
                );";

            string createScansTable = @"
                CREATE TABLE IF NOT EXISTS Scans (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    StartTime TEXT,
                    EndTime TEXT,
                    ScanType TEXT,
                    FilesExamined INTEGER,
                    FilesScanned INTEGER,
                    FilesSkipped INTEGER,
                    ThreatsDetected INTEGER,
                    SuspiciousFiles INTEGER,
                    DefinitionVersion TEXT,
                    Status TEXT
                );";

            string createDetectionsTable = @"
                CREATE TABLE IF NOT EXISTS Detections (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    FilePath TEXT,
                    Engine TEXT,
                    ThreatName TEXT,
                    StaticAnalysisStatus TEXT,
                    ActionTaken TEXT,
                    DetectionTime TEXT
                );";

            string createQuarantineTable = @"
                CREATE TABLE IF NOT EXISTS Quarantine (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    OriginalPath TEXT,
                    QuarantinePath TEXT,
                    ThreatName TEXT,
                    QuarantineTime TEXT,
                    Status TEXT
                );";

            string createSettingsTable = @"
                CREATE TABLE IF NOT EXISTS Settings (
                    Key TEXT PRIMARY KEY,
                    Value TEXT
                );";

            string createExclusionsTable = @"
                CREATE TABLE IF NOT EXISTS Exclusions (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    DirectoryPath TEXT UNIQUE
                );";

            using var cmd = connection.CreateCommand();
            cmd.CommandText = createFilesTable + createScansTable + createDetectionsTable + createQuarantineTable + createSettingsTable + createExclusionsTable;
            cmd.ExecuteNonQuery();
        }

        public FileRecord? GetFileRecord(string filePath)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT Id, FilePath, FileSize, LastModified, Sha256, LastScanTime, ScanResult, DefinitionVersion FROM Files WHERE FilePath = @path;";
            cmd.Parameters.AddWithValue("@path", filePath);

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return new FileRecord
                {
                    Id = reader.GetInt64(0),
                    FilePath = reader.GetString(1),
                    FileSize = reader.GetInt64(2),
                    LastModified = DateTime.Parse(reader.GetString(3)),
                    Sha256 = reader.GetString(4),
                    LastScanTime = DateTime.Parse(reader.GetString(5)),
                    ScanResult = reader.GetString(6),
                    DefinitionVersion = reader.GetString(7)
                };
            }
            return null;
        }

        public void UpsertFileRecord(FileRecord record)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO Files (FilePath, FileSize, LastModified, Sha256, LastScanTime, ScanResult, DefinitionVersion)
                VALUES (@path, @size, @mod, @sha, @scan, @res, @def)
                ON CONFLICT(FilePath) DO UPDATE SET
                    FileSize = @size,
                    LastModified = @mod,
                    Sha256 = @sha,
                    LastScanTime = @scan,
                    ScanResult = @res,
                    DefinitionVersion = @def;";

            cmd.Parameters.AddWithValue("@path", record.FilePath);
            cmd.Parameters.AddWithValue("@size", record.FileSize);
            cmd.Parameters.AddWithValue("@mod", record.LastModified.ToString("o"));
            cmd.Parameters.AddWithValue("@sha", record.Sha256);
            cmd.Parameters.AddWithValue("@scan", record.LastScanTime.ToString("o"));
            cmd.Parameters.AddWithValue("@res", record.ScanResult);
            cmd.Parameters.AddWithValue("@def", record.DefinitionVersion);
            cmd.ExecuteNonQuery();
        }

        public long InsertScanRecord(ScanRecord record)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO Scans (StartTime, EndTime, ScanType, FilesExamined, FilesScanned, FilesSkipped, ThreatsDetected, SuspiciousFiles, DefinitionVersion, Status)
                VALUES (@start, @end, @type, @examined, @scanned, @skipped, @threats, @suspicious, @def, @status);
                SELECT last_insert_rowid();";

            cmd.Parameters.AddWithValue("@start", record.StartTime.ToString("o"));
            cmd.Parameters.AddWithValue("@end", record.EndTime.ToString("o"));
            cmd.Parameters.AddWithValue("@type", record.ScanType);
            cmd.Parameters.AddWithValue("@examined", record.FilesExamined);
            cmd.Parameters.AddWithValue("@scanned", record.FilesScanned);
            cmd.Parameters.AddWithValue("@skipped", record.FilesSkipped);
            cmd.Parameters.AddWithValue("@threats", record.ThreatsDetected);
            cmd.Parameters.AddWithValue("@suspicious", record.SuspiciousFiles);
            cmd.Parameters.AddWithValue("@def", record.DefinitionVersion);
            cmd.Parameters.AddWithValue("@status", record.Status);

            return (long)cmd.ExecuteScalar()!;
        }

        public void InsertDetection(DetectionRecord detection)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO Detections (FilePath, Engine, ThreatName, StaticAnalysisStatus, ActionTaken, DetectionTime)
                VALUES (@path, @engine, @threat, @static, @action, @time);";

            cmd.Parameters.AddWithValue("@path", detection.FilePath);
            cmd.Parameters.AddWithValue("@engine", detection.Engine);
            cmd.Parameters.AddWithValue("@threat", detection.ThreatName);
            cmd.Parameters.AddWithValue("@static", detection.StaticAnalysisStatus);
            cmd.Parameters.AddWithValue("@action", detection.ActionTaken);
            cmd.Parameters.AddWithValue("@time", detection.DetectionTime.ToString("o"));
            cmd.ExecuteNonQuery();
        }

        public void InsertQuarantine(QuarantineRecord record)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO Quarantine (OriginalPath, QuarantinePath, ThreatName, QuarantineTime, Status)
                VALUES (@orig, @qpath, @threat, @qtime, @status);";

            cmd.Parameters.AddWithValue("@orig", record.OriginalPath);
            cmd.Parameters.AddWithValue("@qpath", record.QuarantinePath);
            cmd.Parameters.AddWithValue("@threat", record.ThreatName);
            cmd.Parameters.AddWithValue("@qtime", record.QuarantineTime.ToString("o"));
            cmd.Parameters.AddWithValue("@status", record.Status);
            cmd.ExecuteNonQuery();
        }

        public List<QuarantineRecord> GetQuarantineRecords()
        {
            var list = new List<QuarantineRecord>();
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT Id, OriginalPath, QuarantinePath, ThreatName, QuarantineTime, Status FROM Quarantine WHERE Status = 'Quarantined';";
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(new QuarantineRecord
                {
                    Id = reader.GetInt64(0),
                    OriginalPath = reader.GetString(1),
                    QuarantinePath = reader.GetString(2),
                    ThreatName = reader.GetString(3),
                    QuarantineTime = DateTime.Parse(reader.GetString(4)),
                    Status = reader.GetString(5)
                });
            }
            return list;
        }

        public void UpdateQuarantineStatus(long id, string status)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "UPDATE Quarantine SET Status = @status WHERE Id = @id;";
            cmd.Parameters.AddWithValue("@status", status);
            cmd.Parameters.AddWithValue("@id", id);
            cmd.ExecuteNonQuery();
        }

        public string GetSetting(string key, string defaultValue)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT Value FROM Settings WHERE Key = @key;";
            cmd.Parameters.AddWithValue("@key", key);
            var res = cmd.ExecuteScalar();
            return res != null ? res.ToString()! : defaultValue;
        }

        public void SetSetting(string key, string value)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO Settings (Key, Value) VALUES (@key, @val)
                ON CONFLICT(Key) DO UPDATE SET Value = @val;";
            cmd.Parameters.AddWithValue("@key", key);
            cmd.Parameters.AddWithValue("@val", value);
            cmd.ExecuteNonQuery();
        }

        public List<string> GetExclusions()
        {
            var list = new List<string>();
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT DirectoryPath FROM Exclusions;";
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(reader.GetString(0));
            }
            return list;
        }

        public void AddExclusion(string path)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "INSERT OR IGNORE INTO Exclusions (DirectoryPath) VALUES (@path);";
            cmd.Parameters.AddWithValue("@path", path);
            cmd.ExecuteNonQuery();
        }

        public void RemoveExclusion(string path)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "DELETE FROM Exclusions WHERE DirectoryPath = @path;";
            cmd.Parameters.AddWithValue("@path", path);
            cmd.ExecuteNonQuery();
        }

        public List<ScanRecord> GetScanRecords()
        {
            var list = new List<ScanRecord>();
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT Id, StartTime, EndTime, ScanType, FilesExamined, FilesScanned, FilesSkipped, ThreatsDetected, SuspiciousFiles, DefinitionVersion, Status FROM Scans ORDER BY Id DESC;";
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(new ScanRecord
                {
                    Id = reader.GetInt64(0),
                    StartTime = DateTime.Parse(reader.GetString(1)),
                    EndTime = DateTime.Parse(reader.GetString(2)),
                    ScanType = reader.GetString(3),
                    FilesExamined = reader.GetInt64(4),
                    FilesScanned = reader.GetInt64(5),
                    FilesSkipped = reader.GetInt64(6),
                    ThreatsDetected = reader.GetInt64(7),
                    SuspiciousFiles = reader.GetInt64(8),
                    DefinitionVersion = reader.GetString(9),
                    Status = reader.GetString(10)
                });
            }
            return list;
        }
    }
}
