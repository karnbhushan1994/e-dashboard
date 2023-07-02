const express = require('express');
const { body, validationResult } = require('express-validator');
const app = express();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const jwtSecret = 'e-com';
require('./db/config');
const User = require('./db/User');
const Product = require('./db/Product');
app.use(cors());

// Enable CORS middleware
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

app.use(express.json());

// Validation middleware for handling validation errors
const validate = (validations) => {
  return async (req, res, next) => {
    await Promise.all(validations.map(validation => validation.run(req)));

    const errors = validationResult(req);
    if (errors.isEmpty()) {
      return next();
    }

    res.status(400).json({ errors: errors.array() });
  };
};
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]; // Extract the token from the "Authorization" header

  if (!token) {
    return res.status(401).json({ error: 'Token not found' });
  }

  jwt.verify(token, jwtSecret, (err, valid) => {
    if (err) {
      console.error('Token verification failed:', err); // Log the error for debugging
      return res.status(401).json({ error: 'Invalid token' });
    }

    //req.user = decoded; // Attach the decoded payload to the request object for further use
   // console.log('Token verified:', decoded); // Log the decoded token for debugging
    next();
  });
};


// Register a new user
app.post(
  '/register',
  validate([
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Invalid email'),
    body('password').notEmpty().withMessage('Password is required').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  ]),
  async (req, res) => {
    try {
      const { name, email, password } = req.body;

      // Check if email already exists in the database
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: 'Email already exists' });
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create a new user using the User model
      const user = new User({ name, email, password: hashedPassword });
      // Save the user to the database
      await user.save();
      res.status(201).json({ message: 'User registered successfully', user });
    } catch (error) {
      res.status(500).json({ error: 'An error occurred while registering the user' });
    }
  }
);

// Login

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    // Check if email exists in the database
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Email not found' });
    }
    // Compare the provided password with the hashed password in the database
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    // Generate a JWT token
    const token = jwt.sign({ user }, jwtSecret, { expiresIn: '1h' });

    res.status(200).json({ message: 'User logged in successfully', user, token });

  } catch (error) {
    res.status(500).json({ error: 'An error occurred while logging in' });
  }
});



// Add a new product
app.post('/add-product', [
  body('name').notEmpty().withMessage('Name is required'),
  body('price').notEmpty().withMessage('Price is required'),
  body('company').notEmpty().withMessage('Company is required'),
  body('userId').notEmpty().withMessage('userId is required'),
  body('category').notEmpty().withMessage('Category is required'),
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Create a new product instance
    const product = new Product(req.body);

    // Save the product to the database
    const result = await product.save();

    // Send the result as the response
    res.send(result);
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
});

// Get all products
app.get("/product", verifyToken,async (req, res) => {
  try {
    const products = await Product.find().sort({ _id: -1 });
    res.send(products.length > 0 ? products : "no product");
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while fetching products' });
  }
});


app.delete('/product/:id', async (req, res) => {
  try {
    const productId = req.params.id;
    // Find the product by ID and delete it
    const deletedProduct = await Product.findByIdAndDelete(productId);
    if (!deletedProduct) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json({ message: 'Product deleted successfully', deletedProduct });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while deleting the product' });
  }
});


app.get('/product/:id', async (req, res) => {
  try {
    const productId = req.params.id;
    // Find the product by ID
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json(product);
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while fetching the product' });
  }
});

// Update a product
app.put('/update-product/:id', [
  body('name').notEmpty().withMessage('Name is required'),
  body('price').notEmpty().withMessage('Price is required'),
  body('company').notEmpty().withMessage('Company is required'),
  body('category').notEmpty().withMessage('Category is required'),
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const productId = req.params.id;
    const { name, price, category, company, userId } = req.body;

    // Find the product by ID and update its fields
    const updatedProduct = await Product.findByIdAndUpdate(
      productId,
      { name, price, category, company, userId },
      { new: true }
    );

    if (!updatedProduct) {
      return res.status(404).json({ error: 'Product not found' });
    }

    res.json({ message: 'Product updated successfully', updatedProduct });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while updating the product' });
  }
});

/*app.get("/search/:key", async (req, resp) => {
  try {
    const searchKey = req.params.key; // Get the value of the "key" parameter

    // Perform search operation on the Product collection
    const searchResults = await Product.find({
      name: { $regex: searchKey, $options: "i" }, // Perform a case-insensitive search using regular expression
      category: { $regex: searchKey, $options: "i" },
    });

    // Send the search results as a response
    resp.send(searchResults);
  } catch (error) {
    // Handle any errors that occurred during the search operation
    resp.status(500).json({ error: "An error occurred during the search" });
  }
}); */
app.get("/search/:key", async (req, resp) => {
  try {
    const searchKey = req.params.key; // Get the value of the "key" parameter

    // Perform search operation on the Product collection
    const searchResults = await Product.find({
      $or: [
        { name: { $regex: searchKey, $options: "i" } },
        { category: { $regex: searchKey, $options: "i" } },
      ],
    });

    // Send the search results as a response
    resp.send(searchResults);
  } catch (error) {
    // Handle any errors that occurred during the search operation
    resp.status(500).json({ error: "An error occurred during the search" });
  }
});




// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(5000, () => {
  console.log('Server is running on port 5000');
});
