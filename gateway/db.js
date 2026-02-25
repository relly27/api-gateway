const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://user:password@localhost:5432/security_db'
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool
};
