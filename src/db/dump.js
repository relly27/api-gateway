const path = require('path');
const fs = require('fs');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });
const { exec } = require('child_process');

const user = process.env.DB_USER || 'postgres';
const host = process.env.DB_HOST || 'localhost';
const database = process.env.DB_NAME;
const password = process.env.DB_PASSWORD;
const port = process.env.DB_PORT || 5432;

// Nueva variable para elegir tipo de backup
const backupType = process.env.BACKUP_TYPE || 'full'; // 'schema' o 'full'
const includeData = backupType !== 'schema';

if (!database) {
  console.error('❌ DB_NAME environment variable is not set in your .env file.');
  process.exit(1);
}

const PG_DUMP_PATH = 'C:\\Program Files\\PostgreSQL\\18\\bin\\pg_dump.exe';

if (!fs.existsSync(PG_DUMP_PATH)) {
  console.error(`❌ pg_dump not found at: ${PG_DUMP_PATH}`);
  process.exit(1);
}

console.log(`✅ Found pg_dump at: ${PG_DUMP_PATH}`);

const migrationDir = path.join(__dirname, 'migration');
if (!fs.existsSync(migrationDir)) {
  fs.mkdirSync(migrationDir, { recursive: true });
}

const now = new Date();
const year = now.getFullYear();
const month = String(now.getMonth() + 1).padStart(2, '0');
const day = String(now.getDate()).padStart(2, '0');
const hours = String(now.getHours()).padStart(2, '0');
const minutes = String(now.getMinutes()).padStart(2, '0');

const timestamp = `${year}${month}${day}${hours}${minutes}`;
const typeLabel = includeData ? 'full' : 'schema';
const dumpFile = path.join(migrationDir, `dump-services-${typeLabel}-${timestamp}.sql`);

console.log(`📊 Database: ${database}`);
console.log(`🎯 Host: ${host}:${port}`);
console.log(`👤 User: ${user}`);
console.log(`📦 Backup type: ${includeData ? 'Full (schema + data)' : 'Schema only'}`);
console.log(`💾 Output file: ${dumpFile}`);

const env = { ...process.env, PGPASSWORD: password };

// Construir el comando dinámicamente
const baseCommand = [
  `"${PG_DUMP_PATH}"`,
  `-U ${user}`,
  `-h ${host}`,
  `-p ${port}`,
  `-d ${database}`,
];

// Agregar flags según el tipo de backup
if (!includeData) {
  baseCommand.push('--schema-only');
} else {
  // Opciones recomendadas para backup completo
  baseCommand.push('--encoding=UTF8');
  baseCommand.push('--no-owner');
  baseCommand.push('--no-privileges');
  // Opcional: para poder restaurar sobre una DB existente
  // baseCommand.push('--clean');
  // baseCommand.push('--if-exists');
}

baseCommand.push(`-f "${dumpFile}"`);

const command = baseCommand.join(' ');

console.log(`⚡ Executing command...`);
console.log(`🔧 Command: ${command}`);

exec(command, { env }, (error, stdout, stderr) => {
  if (error) {
    console.error(`❌ Error executing pg_dump: ${error.message}`);
    if (stderr) {
      console.error(`📝 stderr: ${stderr}`);
    }
    process.exit(1);
  }
  
  if (stderr) {
    console.warn(`⚠️  pg_dump warnings: ${stderr}`);
  }
  
  if (fs.existsSync(dumpFile)) {
    const stats = fs.statSync(dumpFile);
    const fileSizeMB = (stats.size / (1024 * 1024)).toFixed(2);
    console.log(`✅ Database ${includeData ? 'full backup' : 'schema'} dumped successfully!`);
    console.log(`📁 File: ${dumpFile}`);
    console.log(`📊 Size: ${fileSizeMB} MB`);
    
    // Pequeña verificación del contenido
    const content = fs.readFileSync(dumpFile, 'utf8').substring(0, 500);
    if (includeData && !content.includes('INSERT INTO') && content.includes('CREATE TABLE')) {
      console.warn(`⚠️  Warning: Backup file appears to contain only schema, no data inserts found.`);
    }
  } else {
    console.error(`❌ Dump file was not created: ${dumpFile}`);
  }
  
  if (stdout) {
    console.log(`📝 stdout: ${stdout}`);
  }
});