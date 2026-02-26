require('dotenv').config();
const express = require('express');
const listEndpoints = require("express-list-endpoints");
const morgan = require("morgan");
const cors = require("cors");

const authRoutes = require('./routes/auth');
const gatewayRoutes = require('./routes/gateway/gatewayRoutes');

const app = express();

// Rate limiting
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

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

// Routes
app.use('/auth', authRoutes);
app.use('/', gatewayRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Something went wrong on the gateway!'
  });
});

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
