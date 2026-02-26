// migrate-simple.js
const path = require('path');
const fs = require('fs');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });
const pool = require('./db');

async function migrate() {
  const client = await pool.connect();
  try {
    let sql = fs.readFileSync(
      path.join(__dirname, 'migration', 'up.sql'), 
      'utf8'
    );
    
    // Eliminar transaction_timeout
    sql = sql.replace(/SET transaction_timeout = 0;\n/g, '');
    
    // Dividir el SQL en secciones
    const sections = sql.split('COPY ');
    
    // Ejecutar primera parte (estructura)
    console.log('Executing schema...');
    await client.query(sections[0]);
    
    // Procesar cada sección COPY
    for (let i = 1; i < sections.length; i++) {
      const section = sections[i];
      const endIndex = section.indexOf('\\.\n');
      
      if (endIndex === -1) continue;
      
      const copyStatement = 'COPY ' + section.substring(0, endIndex);
      const lines = copyStatement.split('\n');
      
      // Extraer tabla y columnas
      const firstLine = lines[0];
      const match = firstLine.match(/COPY (\S+) (\([^)]+\))? FROM stdin;/);
      
      if (!match) continue;
      
      const tableName = match[1];
      const columns = match[2] || '';
      
      // Procesar datos
      for (let j = 1; j < lines.length; j++) {
        const dataLine = lines[j].trim();
        if (!dataLine) continue;
        
        const values = dataLine.split('\t').map(val => {
          if (val === '\\N') return 'NULL';
          return `'${val.replace(/'/g, "''")}'`;
        });
        
        const insertSql = `INSERT INTO ${tableName} ${columns} VALUES (${values.join(', ')});`;
        await client.query(insertSql);
      }
      
      console.log(`Imported data for table: ${tableName}`);
    }
    
    console.log('✅ Migration completed successfully.');
  } catch (err) {
    console.error('❌ Error during migration:', err.message);
    console.error('Stack:', err.stack);
  } finally {
    client.release();
    pool.end();
  }
}

migrate();
