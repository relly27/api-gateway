const { createProxyMiddleware } = require('http-proxy-middleware');
const express = require('express');
const authMiddleware = require('../../middlewares/authMiddleware');
const authorizeMiddleware = require('../../middlewares/authorizeMiddleware');
const auditMiddleware = require('../../middlewares/auditMiddleware');

const router = express.Router();

/**
 * Centralized Proxy Handler.
 * This router applies security middlewares to all incoming requests and
 * dynamically proxies them to the appropriate microservice.
 */
router.all('*',
  authMiddleware,      // 1. Authenticate & prevent spoofing
  authorizeMiddleware, // 2. Check RBAC, Ownership, and find target
  auditMiddleware,     // 3. Log the transaction
  (req, res, next) => {
    const { gatewayConfig } = req;

    // If no target_url is defined, it means this route is either not found
    // or should have been handled by local routes (like /auth).
    if (!gatewayConfig || !gatewayConfig.target_url) {
      return res.status(404).json({
        success: false,
        message: 'No microservice configured for this route'
      });
    }

    // Dynamic proxy configuration
    const proxy = createProxyMiddleware({
      target: gatewayConfig.target_url,
      changeOrigin: true,
      // Pass headers already set in authMiddleware to the downstream service
      onProxyReq: (proxyReq, req, res) => {
        // Fix body if it was already parsed by express.json()
        if (req.body && Object.keys(req.body).length > 0) {
          const bodyData = JSON.stringify(req.body);
          proxyReq.setHeader('Content-Type', 'application/json');
          proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
          proxyReq.write(bodyData);
        }

        // The headers were already set on req.headers by authMiddleware,
        // http-proxy-middleware will forward them by default.
        proxyReq.setHeader('X-Gateway-Request', 'true');
      },
      onError: (err, req, res) => {
        console.error('Proxy error:', err.message);
        if (!res.headersSent) {
          res.status(502).json({
            success: false,
            message: 'Bad Gateway: Microservice unreachable'
          });
        }
      },
      logLevel: 'error'
    });

    // Execute the proxy
    return proxy(req, res, next);
  }
);

module.exports = router;
