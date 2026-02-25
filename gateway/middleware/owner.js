const validateOwner = (paramName = 'userId') => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const resourceOwnerId = req.params[paramName] || req.body[paramName] || req.query[paramName];

    if (!resourceOwnerId) {
      return next(); // Nothing to validate
    }

    if (parseInt(resourceOwnerId) !== req.user.userId) {
      // Allow admin to bypass if needed, but for now strict
      return res.status(403).json({ error: 'Forbidden: You do not own this resource' });
    }

    next();
  };
};

module.exports = validateOwner;
