const { Pool } = require('pg');

// Configuración principal (compatibilidad)
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'postgres',
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
});


// 🔍 VERIFICACIÓN
(async () => {
  console.log('🧪 Probando conexiones...');
  
  try {
    const res1 = await pool.query('SELECT current_database() as db');
    console.log(`✅ BD Principal: ${res1.rows[0].db}`);
  } catch (error) {
    console.error(`❌ BD Principal: ${error.message}`);
  }
  
  console.log('🚀 Conexiones listas\n');
})();

module.exports = pool;