const express = require('express');
const morgan = require('morgan');

const app = express();
app.use(express.json());
app.use(morgan('dev'));

// Demo products
const products = [
  { id: 1, name: 'Laptop', ownerId: 1 },
  { id: 2, name: 'Phone', ownerId: 2 }
];

app.get('/', (req, res) => {
  const userId = req.headers['x-user-id'];
  const userEmail = req.headers['x-user-email'];
  const userDepts = req.headers['x-user-departments'];

  res.json({
    message: 'Product list retrieved successfully',
    userContext: { userId, userEmail, userDepts },
    products
  });
});

app.post('/', (req, res) => {
  const userId = req.headers['x-user-id'];
  const { name } = req.body;

  const newProduct = {
    id: products.length + 1,
    name,
    ownerId: parseInt(userId)
  };
  products.push(newProduct);

  res.status(201).json(newProduct);
});

const PORT = 3002;
app.listen(PORT, () => {
  console.log(`Product Service running on port ${PORT}`);
});
