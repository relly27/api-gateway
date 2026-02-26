const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const dbPath = path.resolve(__dirname, 'security.db');
const db = new sqlite3.Database(dbPath);

// Promisify db.all and db.run to mimic pg.Pool.query
const query = (text, params = []) => {
  return new Promise((resolve, reject) => {
    // Basic conversion from $1, $2 to ? for sqlite if needed,
    // but we'll use ? consistently in our code.
    if (text.trim().toUpperCase().startsWith('SELECT')) {
      db.all(text, params, (err, rows) => {
        if (err) reject(err);
        else resolve({ rows });
      });
    } else {
      db.run(text, params, function(err) {
        if (err) reject(err);
        else resolve({ rows: [], lastID: this.lastID, changes: this.changes });
      });
    }
  });
};

const initDb = async () => {
  const sql = fs.readFileSync(path.resolve(__dirname, 'init.sql'), 'utf8');
  // Split by semicolon and execute each statement
  const statements = sql.split(';').filter(s => s.trim() !== '');
  for (const statement of statements) {
    await query(statement);
  }
  console.log('Database initialized successfully.');
};

module.exports = {
  query,
  initDb,
  db // expose raw db if needed
};
