require('dotenv').config();
const express = require('express');
const listEndpoints = require("express-list-endpoints");
const morgan = require("morgan");
const cors = require("cors");

const app = express();

// Middleware para parsear JSON
app.use(express.json({ limit: '2mb' }));
app.use(morgan("dev"));

// CORS configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*';
app.use(cors({
  origin: allowedOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Mostrar los endpoints disponibles
console.log("Endpoints disponibles:");
console.table(listEndpoints(app));

const host = process.env.HOST || 'localhost';
const PORT = process.env.PORT || 3000;

//dev mode
if (require.main === module) {
  app.listen(PORT, host, () => {
    console.log(`Servidor corriendo en http://${host}:${PORT}`);
  });
}

module.exports = app;
