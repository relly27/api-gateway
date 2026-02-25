const express = require('express');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(express.json());

// Example business logic: Products
const products = [
  { id: 1, name: 'Laptop', category: 'Electronics', price: 1200 },
  { id: 2, name: 'Coffee Mug', category: 'Kitchen', price: 15 }
];

// View products - requires 'view_products' permission (checked at gateway)
app.get('/view', (req, res) => {
  const userId = req.headers['x-user-id'];
  const userEmail = req.headers['x-user-email'];
  const userDepartments = req.headers['x-user-departments'];

  res.json({
    message: 'Products list',
    data: products,
    userContext: { userId, userEmail, userDepartments }
  });
});

// Create product - requires 'create_products' permission (checked at gateway)
app.post('/create', (req, res) => {
  const { name, category, price } = req.body;
  const newProduct = { id: products.length + 1, name, category, price };
  products.push(newProduct);

  res.status(201).json({
    message: 'Product created',
    data: newProduct,
    userContext: { userId: req.headers['x-user-id'] }
  });
});

// User profile - requires owner validation (checked at gateway)
app.get('/profile/:userId', (req, res) => {
  res.json({
    message: 'Profile data',
    userId: req.params.userId,
    requestedBy: req.headers['x-user-id']
  });
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`Example Microservice running on port ${PORT}`);
});

module.exports = app;
