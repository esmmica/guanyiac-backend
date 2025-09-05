require('dotenv').config(); // Load environment variables from .env file

const express = require('express');
const { Pool } = require('pg'); // Instead of mysql2
const cors = require('cors');
const bcrypt = require('bcrypt'); // Make sure you have installed bcrypt: npm install bcrypt
const jwt = require('jsonwebtoken');
const path = require('path'); // NEW: Import path module
const multer = require('multer'); // NEW: Import multer
const fs = require('fs'); // NEW: Import fs module for file system operations
const nodemailer = require('nodemailer'); // {{ NEW: Re-import nodemailer }}

const app = express();
const port = process.env.PORT || 3001; // Backend will run on port 3001 (or specified in .env)

// Middleware
app.use(cors({
    origin: [
        'http://localhost:3000',
        'https://guanyiac-frontend-production.up.railway.app',
        'https://guanyiac.vercel.app'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
})); // Allow requests from your React frontend
app.use(express.json()); // Parse JSON request bodies

// NEW: Ensure 'uploads' directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure Multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir); // Use the dynamically created directory path
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Appending timestamp to file name
    }
});
const upload = multer({ storage: storage });

// Serve static files from the 'uploads' directory
app.use('/uploads', express.static(uploadsDir)); // Use the dynamically created directory path

// MODIFIED: Use MySQL Connection Pool instead of direct connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Test the pool connection (optional, but good for startup check)
pool.query('SELECT NOW()', (err, result) => {
    if (err) {
        console.error('Error connecting to PostgreSQL:', err);
        if (err.code === 'ECONNREFUSED') {
            console.error('Database connection was refused. Check DB credentials or server status.');
        }
        return;
    }
    console.log('Connected to PostgreSQL database via pool');
});

// Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key'; // Use a strong secret in production

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// {{ MODIFIED: Move isAdmin middleware definition here, immediately after authenticateToken }}
function isAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).send('Access Denied: Admins only.');
    }
}

// NEW: Function to update the 'is_new' status for products
const updateNewProductStatus = () => {
    pool.query('SELECT NOW()', (err, result) => { // MODIFIED: use pool.query
        if (err) {
            console.error('Error getting connection for updateNewProductStatus:', err);
            return;
        }

        // This function was not using a transaction, so it doesn't need a pool.getConnection
        // The original code had a pool.getConnection here, which is incorrect for pg.
        // Assuming the intent was to use a transaction if needed, but the original code
        // didn't have a transaction for this specific function.
        // For now, removing the incorrect pool.getConnection.
    });
};

// User registration route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = 'INSERT INTO users (username, password) VALUES ($1, $2)';
        // MODIFIED: Use pool for query
        pool.query(sql, [username, hashedPassword], (err, result) => {
            if (err) {
                if (err.code === '23505') { // ER_DUP_ENTRY
                    return res.status(409).send('Username already exists');
                }
                console.error('Error registering user:', err);
                return res.status(500).send('Error registering user');
            }
            res.status(201).send('User registered successfully');
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        res.status(500).send('Internal server error');
    }
});

// User login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = 'SELECT id, username, password, role, first_name, last_name, email, contact_email FROM users WHERE username = $1';
    // MODIFIED: Use pool for query
    pool.query(sql, [username], async (err, results) => {
        if (err) {
            console.error('Error logging in:', err);
            return res.status(500).send('Error logging in');
        }
        if (results.rows.length === 0) {
            return res.status(400).send('Invalid username or password');
        }

        const user = results.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).send('Invalid username or password');
        }

        const token = jwt.sign(
            {
                id: user.id,
                username: user.username,
                role: user.role,
                first_name: user.first_name,
                last_name: user.last_name,
                email: user.email,
                contact_email: user.contact_email,
            },
            JWT_SECRET,
            { expiresIn: '1h' }
        );
        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
                first_name: user.first_name,
                last_name: user.last_name,
                email: user.email,
                contact_email: user.contact_email,
            }
        });
    });
});

// Get all users (protected route)
app.get('/api/users', authenticateToken, (req, res) => {
    const sql = 'SELECT id, username, role, first_name, last_name, email, contact_email FROM users';
    // MODIFIED: Use pool for query
    pool.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching users:', err);
            return res.status(500).send('Error fetching users');
        }
        res.json(results.rows);
    });
});

// Update user role (protected route)
app.put('/api/users/:id/role', authenticateToken, (req, res) => {
    const userId = req.params.id;
    const { role } = req.body;
    const sql = 'UPDATE users SET role = $1 WHERE id = $2';
    // MODIFIED: Use pool for query
    pool.query(sql, [role, userId], (err, result) => {
        if (err) {
            console.error('Error updating user role:', err);
            return res.status(500).send('Error updating user role');
        }
        if (result.rowCount === 0) {
            return res.status(404).send('User not found');
        }
        res.send('User role updated successfully');
  });
});

// Delete user (protected route)
app.delete('/api/users/:id', authenticateToken, (req, res) => {
    const userId = req.params.id;
    const sql = 'DELETE FROM users WHERE id = $1';
    // MODIFIED: Use pool for query
    pool.query(sql, [userId], (err, result) => {
        if (err) {
            console.error('Error deleting user:', err);
            return res.status(500).send('Error deleting user');
        }
        if (result.rowCount === 0) {
            return res.status(404).send('User not found');
        }
        res.send('User deleted successfully');
  });
});

// Categories API
app.post('/api/categories', (req, res) => {
    const { name } = req.body;
    const sql = 'INSERT INTO categories (name) VALUES ($1)';
    // MODIFIED: Use pool for query
    pool.query(sql, [name], (err, result) => {
        if (err) {
            if (err.code === '23505') { // ER_DUP_ENTRY
                return res.status(409).send('Category with this name already exists.');
            }
            console.error('Error adding category:', err);
            return res.status(500).send('Error adding category');
        }
        res.status(201).json({ id: result.rows[0].id, name });
    });
});

app.get('/api/categories', (req, res) => {
    // Fetch categories with their applications and sub-items
    const sql = `
        SELECT
            c.id AS category_id,
            c.name AS category_name,
            a.id AS app_id,
            a.name AS app_name,
            a.parent_id AS app_parent_id
        FROM
            categories c
        LEFT JOIN
            applications a ON c.id = a.category_id
        ORDER BY
            c.name, a.parent_id, a.name;
    `;

    // MODIFIED: Use pool for query
    pool.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching categories and applications:', err);
            return res.status(500).send('Error fetching data');
        }

        const categoriesMap = new Map();

        results.rows.forEach(row => {
            if (!categoriesMap.has(row.category_id)) {
                categoriesMap.set(row.category_id, {
                    id: row.category_id,
                    name: row.category_name,
                    applications: []
                });
            }

            if (row.app_id) {
                const category = categoriesMap.get(row.category_id);
                // Check if it's a top-level application or a sub-item
                if (row.app_parent_id === null) {
                    // Top-level application
                    let existingApp = category.applications.find(app => app.id === row.app_id);
                    if (!existingApp) {
                        existingApp = { id: row.app_id, name: row.app_name, parent_id: null, subItems: [] };
                        category.applications.push(existingApp);
                    }
                } else {
                    // Sub-item, find its parent application
                    const parentApp = category.applications.find(app => app.id === row.app_parent_id);
                    if (parentApp) {
                        // Ensure subItems array exists
                        if (!parentApp.subItems) {
                            parentApp.subItems = [];
                        }
                        // Add sub-item if not already present
                        if (!parentApp.subItems.some(sub => sub.id === row.app_id)) {
                            parentApp.subItems.push({ id: row.app_id, name: row.app_name, parent_id: row.app_parent_id });
                        }
                    } else {
                        // Handle cases where a sub-item's parent is not found (e.g., if parent is also a sub-item)
                        // For simplicity, we'll assume only one level of sub-items for now based on current schema.
                        // If multi-level sub-items are needed, this logic requires a recursive approach.
                        console.warn(`Sub-item ${row.app_name} (${row.app_id}) found without direct parent application in category ${row.category_name}`);
                    }
                }
            }
        });

        // Sort applications and sub-items alphabetically within each category for consistent order
        categoriesMap.forEach(category => {
            category.applications.sort((a, b) => a.name.localeCompare(b.name));
            category.applications.forEach(app => {
                if (app.subItems) {
                    app.subItems.sort((a, b) => a.name.localeCompare(b.name));
                }
            });
        });

        res.json(Array.from(categoriesMap.values()));
    });
});

app.put('/api/categories/:id', (req, res) => {
    const categoryId = req.params.id;
    const { name } = req.body;
    const sql = 'UPDATE categories SET name = $1 WHERE id = $2';
    // MODIFIED: Use pool for query
    pool.query(sql, [name, categoryId], (err, result) => {
        if (err) {
            if (err.code === '23505') { // ER_DUP_ENTRY
                return res.status(409).send('Category with this name already exists.');
            }
            console.error('Error updating category:', err);
            return res.status(500).send('Error updating category');
        }
        if (result.rowCount === 0) {
            return res.status(404).send('Category not found');
        }
        res.send('Category updated successfully');
    });
});

app.delete('/api/categories/:id', (req, res) => {
    const categoryId = req.params.id;

    // MODIFIED: Use pool.getConnection for transactions
    pool.query('SELECT NOW()', (err, connection) => { // MODIFIED: use connection for queries
        if (err) {
            console.error('Error getting connection from pool:', err);
            return res.status(500).send('Database connection error');
        }

        connection.beginTransaction(err => {
            if (err) {
                
                console.error('Error starting transaction:', err);
                return res.status(500).send('Internal server error');
            }

            const deleteApplicationsSql = 'DELETE FROM applications WHERE category_id = $1';
            connection.query(deleteApplicationsSql, [categoryId], (err, result) => {
                if (err) {
                    return connection.rollback(() => {
                        
                        console.error('Error deleting applications:', err);
                        res.status(500).send('Error deleting associated applications');
                    });
                }

                const deleteCategorySql = 'DELETE FROM categories WHERE id = $1';
                connection.query(deleteCategorySql, [categoryId], (err, result) => {
                    if (err) {
                        return connection.rollback(() => {
                            
                            console.error('Error deleting category:', err);
                            res.status(500).send('Error deleting category');
                        });
                    }
                    if (result.rowCount === 0) {
                        return connection.rollback(() => {
                            
                            res.status(404).send('Category not found');
                        });
                    }

                    connection.commit(err => {
                        if (err) {
                            return connection.rollback(() => {
                                
                                console.error('Error committing transaction:', err);
                                res.status(500).send('Internal server error');
                            });
                        }
                         // Release the connection back to the pool
                        res.send('Category and associated applications deleted successfully');
                    });
                });
            });
        });
    });
});

// Applications (including sub-items) API
app.post('/api/applications', (req, res) => {
  const { name, category_id, parent_id } = req.body;
  const sql = 'INSERT INTO applications (name, category_id, parent_id) VALUES ($1, $2, $3)';
    // MODIFIED: Use pool for query
    pool.query(sql, [name, category_id, parent_id], (err, result) => {
    if (err) {
      if (err.code === '23505') { // ER_DUP_ENTRY
                // Check if the duplicate entry is for the same parent_id
                const checkSql = 'SELECT id FROM applications WHERE name = $1 AND category_id = $2 AND parent_id = $3';
                // MODIFIED: Use pool for checkSql query
                pool.query(checkSql, [name, category_id, parent_id], (checkErr, checkResults) => {
                    if (checkErr) {
                        console.error('Error checking duplicate application:', checkErr);
                        return res.status(500).send('Error adding application');
                    }
                    if (checkResults.rows.length > 0) {
                        return res.status(409).send('An item with this name already exists in this category/parent.');
                    }
                    // If it's a duplicate but not for the specific parent, it's a different kind of error
                    console.error('Error adding application (duplicate not matching parent):', err);
                    return res.status(500).send('Error adding application');
                });
                return; // Exit to prevent further execution in case of duplicate entry
            }
            console.error('Error adding application:', err);
            return res.status(500).send('Error adding application');
        }
        res.status(201).json({ id: result.rows[0].id, name, category_id, parent_id });
  });
});

app.put('/api/applications/:id', (req, res) => {
    const appId = req.params.id;
  const { name } = req.body;
  const sql = 'UPDATE applications SET name = $1 WHERE id = $2';
    // MODIFIED: Use pool for query
    pool.query(sql, [name, appId], (err, result) => {
    if (err) {
      if (err.code === '23505') { // ER_DUP_ENTRY
                return res.status(409).send('An item with this name already exists.');
       }
            console.error('Error updating application:', err);
            return res.status(500).send('Error updating application');
    }
    if (result.rowCount === 0) {
            return res.status(404).send('Application not found');
    }
        res.send('Application updated successfully');
  });
});

app.delete('/api/applications/:id', (req, res) => {
    const appId = req.params.id;

    // MODIFIED: Use pool.getConnection for transactions
    pool.query('SELECT NOW()', (err, connection) => { // MODIFIED: use connection for queries
    if (err) {
            console.error('Error getting connection from pool:', err);
            return res.status(500).send('Database connection error');
        }

        connection.beginTransaction(err => {
    if (err) {
                
                console.error('Error starting transaction for app delete:', err);
                return res.status(500).send('Internal server error');
            }

            // First, recursively delete any sub-items of this application
            const deleteSubItemsRecursively = (currentAppId, callback) => {
                const selectSubItemsSql = 'SELECT id FROM applications WHERE parent_id = $1';
                connection.query(selectSubItemsSql, [currentAppId], (err, subItems) => { // MODIFIED: use connection for queries
                    if (err) return callback(err);

                    if (subItems.rows.length === 0) {
                        return callback(null); // No more sub-items
                    }

                    let completed = 0;
                    subItems.rows.forEach(subItem => {
                        deleteSubItemsRecursively(subItem.id, (err) => {
                            if (err) return callback(err);
                            const deleteSql = 'DELETE FROM applications WHERE id = $1';
                            connection.query(deleteSql, [subItem.id], (err) => { // MODIFIED: use connection for queries
                                if (err) return callback(err);
                                completed++;
                                if (completed === subItems.rows.length) {
                                    callback(null);
                                }
                            });
                        });
  });
});
            };

            deleteSubItemsRecursively(appId, (err) => {
                if (err) {
                    return connection.rollback(() => {
                        
                        console.error('Error deleting sub-items recursively:', err);
                        res.status(500).send('Error deleting associated sub-items');
                    });
                }

                // After all sub-items are deleted, delete the application itself
                const deleteAppSql = 'DELETE FROM applications WHERE id = $1';
                connection.query(deleteAppSql, [appId], (err, result) => { // MODIFIED: use connection for queries
                    if (err) {
                        return connection.rollback(() => {
                            
                            console.error('Error deleting application:', err);
                            res.status(500).send('Error deleting application');
                        });
                    }
                    if (result.rowCount === 0) {
                        return connection.rollback(() => {
                            
                            res.status(404).send('Application not found');
                        });
                    }

                    connection.commit(err => {
                        if (err) {
                            return connection.rollback(() => {
                                
                                console.error('Error committing transaction:', err);
                                res.status(500).send('Internal server error');
                            });
                        }
                         // Release the connection back to the pool
                        res.send('Application and all its sub-items deleted successfully');
                    });
                });
            });
        });
    });
});

// Products API

// MODIFIED: POST route to add a new product with file upload and product_features
app.post('/api/products', upload.single('image'), (req, res) => { // 'image' is the field name from FormData
    const { name, application_id, brand, temperature_range, material, description, is_new, specs, product_features } = req.body;
    // req.file will contain the uploaded image details
    const image_url = req.file ? `/uploads/${req.file.filename}` : (req.body.image_url_fallback || null);

    // {{ REMOVED: console.log for brevity, but you can keep them for debugging if needed }}
    // console.log('Received product_features for new product:', product_features);
    // console.log('Type of received product_features:', typeof product_features);

    // Validate required fields
    if (!name || !application_id || !brand || !temperature_range || !material) {
        return res.status(400).send('Missing required product fields.');
    }

    pool.query('SELECT NOW()', (err, connection) => { // MODIFIED: use connection for queries
        if (err) {
            console.error('Error getting connection from pool:', err);
            return res.status(500).send('Database connection error');
        }

        connection.beginTransaction(err => {
            if (err) {
                
                console.error('Error starting transaction:', err);
                return res.status(500).send('Internal server error');
            }

            const insertProductQuery = `INSERT INTO products (name, application_id, brand, temperature_range, material, image_url, description, is_new, product_features) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`;
            // MODIFIED: Removed JSON.parse() here. product_features is already a JSON string.
            connection.query(insertProductQuery, [name, application_id, brand, temperature_range, material, image_url, description, is_new, product_features], (err, productResult) => {
                if (err) {
                    if (err.code === '23505') { // ER_DUP_ENTRY
                    return connection.rollback(() => {
                        
                            res.status(409).send('Product with this name already exists.')
                        });
                    }
                    console.error('Error adding product:', err);
                    return connection.rollback(() => {
                        
                        res.status(500).send('Error adding product')
                    });
                }

                const productId = productResult.rows[0].id;
                const parsedSpecs = JSON.parse(specs); // Parse the stringified specs array

                if (parsedSpecs.length === 0) {
                    return connection.commit(err => {
                        if (err) {
                            return connection.rollback(() => {
                                
                                res.status(500).send('Internal server error')
                            });
                        }
                         // Release the connection back to the pool
                        res.status(201).json({ id: productId, message: 'Product added successfully with no specs.' });
                    });
                }

                const insertSpecQuery = `INSERT INTO product_specs (product_id, model_series, color, sap, nom_id, nom_od, max_wp, weight) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`;
                const specValues = parsedSpecs.map(spec => [
                    productId,
                    spec.model_series,
                    spec.color,
                    spec.sap,
                    spec.nom_id,
                    spec.nom_od,
                    spec.max_wp,
                    spec.weight,
                ]);

                connection.query(insertSpecQuery, [specValues], (err, specResult) => {
                    if (err) {
                        console.error('Error adding product specs:', err);
                                return connection.rollback(() => {
                                    
                            res.status(500).send('Error adding product specifications')
                                });
                            }
                    connection.commit(err => {
                        if (err) {
                            return connection.rollback(() => {
                            
                                res.status(500).send('Internal server error')
                            });
                        }
                         // Release the connection back to the pool
                        res.status(201).json({ id: productId, message: 'Product added successfully with specs.' });
                    });
                    });
            });
        });
    });
});

app.get('/api/products', (req, res) => {
    // NEW: Get all potential filter query parameters
    const {
        is_new,
        search,
        application_ids, // comma-separated string of application IDs
        minTemp, maxTemp,
        minWeight, maxWeight,
        minDiameter, maxDiameter,
        minPressure, maxPressure
    } = req.query;

    let sql = `
        SELECT
            p.id, p.name, p.application_id, p.brand, p.temperature_range, p.material, p.image_url, p.description, p.is_new, p.product_features,
            s.id AS spec_id, s.model_series, s.color, s.sap, s.nom_id, s.nom_od, s.max_wp, s.weight
        FROM
            products p
        LEFT JOIN
            product_specs s ON p.id = s.product_id
    `;
    const whereConditions = [];
    const queryParams = [];

    // 1. Filter by 'is_new' status
    if (is_new !== undefined) {
        whereConditions.push(`p.is_new = $1`);
        queryParams.push(is_new === 'true' || is_new === '1' ? 1 : 0);
    }

    // 2. Filter by search term (product name or description)
    if (search) {
        whereConditions.push(`(p.name LIKE $1 OR p.description LIKE $1)`);
        queryParams.push(`%${search}%`, `%${search}%`);
    }

    // 3. Filter by application_ids (allows multiple IDs)
    if (application_ids) {
        const ids = application_ids.split(',').map(id => parseInt(id.trim())).filter(id => !isNaN(id));
        if (ids.length > 0) {
            whereConditions.push(`p.application_id IN ($1)`);
            queryParams.push(ids);
        }
    }

    // 4. Filter by Temperature Range
    // Assumes p.temperature_range is like "X to Y" or "X"
    if (minTemp !== undefined && maxTemp !== undefined) {
        const minT = parseFloat(minTemp);
        const maxT = parseFloat(maxTemp);
        if (!isNaN(minT) && !isNaN(maxT)) {
            // Extract the first numerical value from temperature_range (e.g., "-65" from "-65 to 300")
            // This is a heuristic and might need adjustment if your temperature_range strings vary.
            whereConditions.push(`
                CAST(
                    TRIM(
                        SUBSTRING_INDEX(
                            REPLACE(p.temperature_range, '°', ''),
                            ' to ',
                            1
                        )
                    ) AS SIGNED
                ) BETWEEN $1 AND $2
            `);
            queryParams.push(minT, maxT);
        }
    }

    // 5. Filter by Weight Range (from product_specs.weight - kg/m part)
    // Uses EXISTS to check if at least one spec row for the product matches the criteria.
    if (minWeight !== undefined && maxWeight !== undefined) {
        const minW = parseFloat(minWeight);
        const maxW = parseFloat(maxWeight);
        if (!isNaN(minW) && !isNaN(maxW)) {
            whereConditions.push(`EXISTS (
                SELECT 1 FROM product_specs ps_w
                WHERE ps_w.product_id = p.id AND
                CAST(
                    TRIM(
                        SUBSTRING_INDEX(
                            SUBSTRING_INDEX(ps_w.weight, '(', -1),
                            'kg/m)',
                            1
                        )
                    ) AS DECIMAL(10,2)
                ) BETWEEN $1 AND $2
            )`);
            queryParams.push(minW, maxW);
        }
    }

    // 6. Filter by Diameter Range (from product_specs.nom_id or nom_od - mm part)
    if (minDiameter !== undefined && maxDiameter !== undefined) {
        const minD = parseFloat(minDiameter);
        const maxD = parseFloat(maxDiameter);
        if (!isNaN(minD) && !isNaN(maxD)) {
            whereConditions.push(`EXISTS (
                SELECT 1 FROM product_specs ps_d
                WHERE ps_d.product_id = p.id AND (
                    CAST(
                        TRIM(
                            SUBSTRING_INDEX(
                                SUBSTRING_INDEX(ps_d.nom_id, '(', -1),
                                'mm)',
                                1
                            )
                        ) AS DECIMAL(10,2)
                    ) BETWEEN $1 AND $2
                    OR
                    CAST(
                        TRIM(
                            SUBSTRING_INDEX(
                                SUBSTRING_INDEX(ps_d.nom_od, '(', -1),
                                'mm)',
                                1
                            )
                        ) AS DECIMAL(10,2)
                    ) BETWEEN $3 AND $4
                )
            )`);
            queryParams.push(minD, maxD, minD, maxD);
        }
    }

    // 7. Filter by Working Pressure Range (from product_specs.max_wp - Psi part)
    if (minPressure !== undefined && maxPressure !== undefined) {
        const minP = parseFloat(minPressure);
        const maxP = parseFloat(maxPressure);
        if (!isNaN(minP) && !isNaN(maxP)) {
            whereConditions.push(`EXISTS (
                SELECT 1 FROM product_specs ps_p
                WHERE ps_p.product_id = p.id AND
                CAST(
                    TRIM(
                        SUBSTRING_INDEX(ps_p.max_wp, ' (', 1)
                    ) AS SIGNED
                ) BETWEEN $1 AND $2
            )`);
            queryParams.push(minP, maxP);
        }
    }


    if (whereConditions.length > 0) {
        // Use a subquery to ensure each product is only returned once, even if it has multiple specs matching filters
        sql += ` WHERE p.id IN (
            SELECT p_filtered.id
            FROM products p_filtered
            LEFT JOIN product_specs s_filtered ON p_filtered.id = s_filtered.product_id
            WHERE ` + whereConditions.join(' AND ') + `
            GROUP BY p_filtered.id
        )`;
    }

    // Final ordering
    sql += ` ORDER BY p.name, s.model_series, s.color, s.sap;`;

    pool.query(sql, queryParams, (err, results) => {
        if (err) {
            console.error('Error fetching products with filters:', err);
            return res.status(500).send('Error fetching products with filters');
        }

        const productsMap = new Map();

        results.rows.forEach(row => {
            if (!productsMap.has(row.id)) {
                // {{ NEW: Ensure product_features is parsed here for the /api/products route }}
                let parsedProductFeatures = [];
                if (typeof row.product_features === 'string') {
                    try {
                        parsedProductFeatures = JSON.parse(row.product_features);
                    } catch (e) {
                        console.error('Error parsing product_features JSON from product list:', e);
                        // If parsing fails, default to an empty array
                        parsedProductFeatures = [];
                    }
                } else if (row.product_features) {
                    // If it's already an object (e.g., if MySQL driver does auto-parsing), use it
                    parsedProductFeatures = row.product_features;
                }
                // If it's NULL, it will correctly remain an empty array.

                productsMap.set(row.id, {
                    id: row.id,
                    name: row.name,
                    application_id: row.application_id,
                    brand: row.brand,
                    temperature_range: row.temperature_range,
                    material: row.material,
                    image_url: row.image_url,
                    description: row.description,
                    is_new: row.is_new,
                    product_features: parsedProductFeatures, // Use the parsed (or default empty) array
                    specs: []
                });
            }

            if (row.spec_id) {
                productsMap.get(row.id).specs.push({
                    id: row.spec_id,
                    model_series: row.model_series,
                    color: row.color,
                    sap: row.sap,
                    nom_id: row.nom_id,
                    nom_od: row.nom_od,
                    max_wp: row.max_wp,
                    weight: row.weight,
                });
            }
        });

        res.json(Array.from(productsMap.values()));
    });
});

// MODIFIED: PUT route to update product with file upload and product_features
app.put('/api/products/:id', upload.single('image'), (req, res) => { // 'image' is the field name from FormData
    const productId = req.params.id;
    const { name, application_id, brand, temperature_range, material, description, is_new, specs, product_features, image_url_fallback, clear_image } = req.body;

    let image_url = null;
    if (req.file) {
        // New file uploaded, use its path
        image_url = `/uploads/${req.file.filename}`;
    } else if (clear_image === 'true') {
        // User explicitly chose to remove the image
        image_url = null;
    } else {
        // No new file, and not clearing, so retain existing image_url_fallback (if any)
        image_url = image_url_fallback || null;
    }

    // {{ REMOVED: console.log for brevity, but you can keep them for debugging if needed }}
    // console.log('Received product_features for updating product:', product_features);
    // console.log('Type of received product_features:', typeof product_features);

    // Validate required fields
    if (!name || !application_id || !brand || !temperature_range || !material) {
        return res.status(400).send('Missing required product fields.');
    }

    pool.query('SELECT NOW()', (err, connection) => { // MODIFIED: use connection for queries
        if (err) {
            console.error('Error getting connection from pool:', err);
            return res.status(500).send('Database connection error');
        }

        connection.beginTransaction(err => {
            if (err) {
                
                console.error('Error starting transaction:', err);
                return res.status(500).send('Internal server error');
            }

            const updateProductQuery = `UPDATE products SET name = $1, application_id = $2, brand = $3, temperature_range = $4, material = $5, image_url = $6, description = $7, is_new = $8, product_features = $9 WHERE id = $10`;
            connection.query(updateProductQuery, [name, application_id, brand, temperature_range, material, image_url, description, is_new, product_features, productId], (err, productResult) => {
                if (err) {
                    if (err.code === '23505') { // ER_DUP_ENTRY
                    return connection.rollback(() => {
                        
                            res.status(409).send('Product with this name already exists.')
                        });
                    }
                    console.error('Error updating product:', err);
                        return connection.rollback(() => {
                            
                        res.status(500).send('Error updating product')
                    });
                }

                // Delete existing specs for this product before inserting new ones
                const deleteSpecsQuery = `DELETE FROM product_specs WHERE product_id = $1`;
                connection.query(deleteSpecsQuery, [productId], (err) => {
                    if (err) {
                        console.error('Error deleting existing product specs:', err);
                                return connection.rollback(() => {
                         
                            res.status(500).send('Error updating product specifications')
                        });
                    }

                    const parsedSpecs = JSON.parse(specs);

                    if (parsedSpecs.length === 0) {
                        return connection.commit(err => {
                            if (err) {
                        return connection.rollback(() => {
                            
                                    res.status(500).send('Internal server error')
                                });
                            }
                             // Release the connection back to the pool
                            res.send('Product updated successfully with no specs.');
                        });
                    }

                    const insertSpecQuery = `INSERT INTO product_specs (product_id, model_series, color, sap, nom_id, nom_od, max_wp, weight) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`;
                    const specValues = parsedSpecs.map(spec => [
                        productId,
                        spec.model_series,
                        spec.color,
                        spec.sap,
                        spec.nom_id,
                        spec.nom_od,
                        spec.max_wp,
                        spec.weight,
                    ]);

                    connection.query(insertSpecQuery, [specValues], (err, specResult) => {
                        if (err) {
                            console.error('Error inserting new product specs:', err);
                                return connection.rollback(() => {
                                    
                                res.status(500).send('Error updating product specifications')
                                });
                            }
                        connection.commit(err => {
                            if (err) {
                                    return connection.rollback(() => {
                                        
                                    res.status(500).send('Internal server error')
                        });
                    }
                             // Release the connection back to the pool
                            res.send('Product updated successfully with specs.');
                        });
                        });
                });
            });
        });
    });
});

app.delete('/api/products/:id', (req, res) => {
    const productId = req.params.id;

    // MODIFIED: Use pool.getConnection for transactions
    pool.query('SELECT NOW()', (err, connection) => { // MODIFIED: use connection for queries
        if (err) {
            console.error('Error getting connection from pool:', err);
            return res.status(500).send('Database connection error');
        }

        connection.beginTransaction(err => {
            if (err) {
                
                console.error('Error starting transaction:', err);
                return res.status(500).send('Internal server error');
            }

            // Delete associated product specs first
            const deleteSpecsSql = 'DELETE FROM product_specs WHERE product_id = $1';
            connection.query(deleteSpecsSql, [productId], (err, specResult) => {
                if (err) {
                                return connection.rollback(() => {
                                    
                        console.error('Error deleting product specs:', err);
                        res.status(500).send('Error deleting associated specifications');
                    });
                }

                // Then delete the product itself
                const deleteProductSql = 'DELETE FROM products WHERE id = $1';
                connection.query(deleteProductSql, [productId], (err, productResult) => {
                    if (err) {
                        return connection.rollback(() => {
                            
                            console.error('Error deleting product:', err);
                            res.status(500).send('Error deleting product');
                        });
                    }
                    if (productResult.rowCount === 0) {
                        return connection.rollback(() => {
                            
                            res.status(404).send('Product not found');
                        });
                    }

                    connection.commit(err => {
                        if (err) {
                            return connection.rollback(() => {
                                
                                console.error('Error committing transaction:', err);
                                res.status(500).send('Internal server error');
                            });
                        }
                         // Release the connection back to the pool
                        res.send('Product and its specifications deleted successfully');
                    });
                });
            });
        });
    });
});

// MODIFIED: Get product by ID (for ProductDetailPage) to include product_features
// MODIFIED: Get product by ID (for ProductDetailPage) to include product_features
app.get('/api/products/:productId', (req, res) => {
    const productId = req.params.productId;

    const productSql = 'SELECT *, product_features FROM products WHERE id = $1';
    const specsSql = 'SELECT * FROM product_specs WHERE product_id = $1 ORDER BY id ASC';

    // Use Promise.all to fetch product and specs concurrently
    Promise.all([
        new Promise((resolve, reject) => {
            pool.query(productSql, [productId], (err, productResults) => {
                if (err) return reject(err);
                resolve(productResults.rows[0]);
            });
        }),
        new Promise((resolve, reject) => {
            pool.query(specsSql, [productId], (err, specsResults) => {
                if (err) return reject(err);
                resolve(specsResults.rows);
            });
        })
    ])
    .then(([product, specs]) => {
        if (!product) {
            return res.status(404).send('Product not found');
        }

        // Ensure product_features is parsed if it's coming as a string
        if (typeof product.product_features === 'string') {
            try {
                product.product_features = JSON.parse(product.product_features);
            } catch (e) {
                console.error('Error parsing product_features JSON:', e);
                product.product_features = []; // Default to empty array on parse error
            }
        } else if (!product.product_features) {
            product.product_features = []; // Ensure it's an array even if null
        }

        // Attach specs to the product object
        product.product_specs = specs;

        res.json(product);
    })
    .catch(queryErr => {
        console.error('Error fetching product details or specs:', queryErr);
        res.status(500).send('Error fetching product details');
    });
});

// Add Product Type (Application)
app.post('/api/product-types', authenticateToken, (req, res) => {
    // ... existing code ...
});

// NEW: Inquiry API Routes
// Route to submit a new inquiry
app.post('/api/inquiries', (req, res) => {
    // Accept both styles for compatibility
    const { customer_first_name, customer_last_name, customer_name, customer_email, customer_message, inquiry_items } = req.body;
    // Prefer first/last if present, else use customer_name
    const finalCustomerName = customer_first_name && customer_last_name
      ? `${customer_first_name} ${customer_last_name}`
      : (customer_name || '');
    const inquiryItemsJson = JSON.stringify(inquiry_items);

    const sql = 'INSERT INTO inquiries (customer_name, customer_email, customer_message, inquiry_items, is_read) VALUES ($1, $2, $3, $4, $5)';
    pool.query(sql, [finalCustomerName, customer_email, customer_message, inquiryItemsJson, 0], (err, result) => {
        if (err) {
            console.error('Error submitting inquiry:', err);
            return res.status(500).send('Error submitting inquiry');
        }
        res.status(201).send('Inquiry submitted successfully');
    });
});

// Route to get all inquiries (Protected for Admin)
app.get('/api/inquiries', authenticateToken, (req, res) => {
    // {{ MODIFIED: Select the is_read column }}
    const sql = 'SELECT id, customer_name, customer_email, customer_message, inquiry_items, created_at, is_read FROM inquiries ORDER BY created_at DESC';
    pool.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching inquiries:', err);
            return res.status(500).send('Error fetching inquiries');
        }

        // Parse the JSON string back into an object/array for each inquiry_items field
        const inquiriesWithParsedItems = results.rows.map(inquiry => {
            let parsedItems = [];
            try {
                parsedItems = inquiry.inquiry_items ? JSON.parse(inquiry.inquiry_items) : [];
                // If it's already an array, do nothing
                if (!Array.isArray(parsedItems)) parsedItems = [];
            } catch (e) {
                parsedItems = [];
            }
            return {
                ...inquiry,
                inquiry_items: parsedItems
            };
        });

        res.json(inquiriesWithParsedItems);
    });
});

// {{ NEW: Route to mark an inquiry as read }}
app.put('/api/inquiries/:id/read', authenticateToken, (req, res) => {
    const inquiryId = req.params.id;
    const sql = 'UPDATE inquiries SET is_read = $1 WHERE id = $2';
    pool.query(sql, [1, inquiryId], (err, result) => {
        if (err) {
            console.error('Error marking inquiry as read:', err);
            return res.status(500).send('Error marking inquiry as read');
        }
        if (result.rowCount === 0) {
            return res.status(404).send('Inquiry not found');
        }
        res.send('Inquiry marked as read successfully');
    });
});

// {{ NEW: Nodemailer Transporter Configuration (re-added) }}
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST, // e.g., 'smtp.gmail.com'
    port: process.env.EMAIL_PORT, // e.g., 587 for TLS, 465 for SSL
    secure: process.env.EMAIL_PORT == 465, // Use true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER, // Your email address for sending
        pass: process.env.EMAIL_PASS, // Your email password or app-specific password
    },
});

// {{ NEW: In-memory store for verification codes (for demo purposes) }}
const verificationCodes = new Map();

// {{ MODIFIED: Route to initiate adding a new user (admin only) - Phase 1: Send verification email }}
app.post('/api/admin/users/initiate-add', authenticateToken, isAdmin, async (req, res) => {
    // The admin performing the action needs to confirm their identity.
    // We send a code to the logged-in admin's main email (req.user.email, from their login).
    const adminEmailForVerification = req.user.email; // Assuming admin's 'email' column holds their actual email
    const adminId = req.user.id;
    // {{ MODIFIED: Destructure new_username (for login) and new_contact_email }}
    const { new_username, new_password, new_first_name, new_last_name, new_role, new_contact_email } = req.body;

    // {{ MODIFIED: Update validation logic to reflect new field names }}
    if (!new_username || !new_password || !new_first_name || !new_last_name || !new_role) {
        return res.status(400).send('Missing required fields for new user.');
    }
    // contact_email is optional, so no direct 'required' validation here on backend.
    // Frontend will handle conditional requirements for admin role.

    // Generate a 6-digit verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000; // Code valid for 10 minutes

    // Store the code and pending user data
    verificationCodes.set(adminId, {
        code: verificationCode,
        expires: expiresAt,
        // {{ MODIFIED: Store new_username (for login) and new_contact_email }}
        pendingUserData: { new_username, new_password, new_first_name, new_last_name, new_role, new_contact_email }
    });

    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: adminEmailForVerification, // Send to the logged-in admin's contact email
            subject: 'User Creation Verification Code',
            html: `
                <p>Hello Admin,</p>
                <p>You recently initiated the creation of a new user account on the GUANYIAC Admin Panel.</p>
                <p>To confirm this action, please use the following verification code:</p>
                <h3 style="color: #2f615d;">${verificationCode}</h3>
                <p>This code is valid for 10 minutes.</p>
                <p>If you did not request this, please ignore this email.</p>
                <p>Thank you,</p>
                <p>The GUANYIAC Team</p>
            `,
        });
        res.status(200).send('Verification code sent to your email.');
    } catch (error) {
        console.error('Error sending verification email:', error);
        verificationCodes.delete(adminId); // Clear pending data if email fails
        let errorMessage = 'Failed to send verification email. Check backend logs and Nodemailer configuration (especially .env values).';
        if (error.response && error.response.command) {
            errorMessage += ` SMTP Error: ${error.response.command} - ${error.response.code} - ${error.response.response}`;
        }
        res.status(500).send(errorMessage);
    }
});

// {{ MODIFIED: Route to confirm adding a new user (admin only) - Phase 2: Verify code and create user }}
app.post('/api/admin/users/confirm-add', authenticateToken, isAdmin, async (req, res) => {
    const adminId = req.user.id;
    const { verification_code } = req.body;

    const storedData = verificationCodes.get(adminId);

    if (!storedData || storedData.code !== verification_code || Date.now() > storedData.expires) {
        // Clear the code if it's invalid or expired
        verificationCodes.delete(adminId);
        return res.status(400).send('Invalid or expired verification code.');
    }

    // Code is valid, proceed with user creation
    // {{ MODIFIED: Destructure new_username (for login) and new_contact_email }}
    const { new_username, new_password, new_first_name, new_last_name, new_role, new_contact_email } = storedData.pendingUserData;

    try {
        const hashedPassword = await bcrypt.hash(new_password, 10);
        // {{ MODIFIED: Insert new user with username (for login) and contact_email }}
        const sql = 'INSERT INTO users (username, password, first_name, last_name, role, email, contact_email) VALUES ($1, $2, $3, $4, $5, $6, $7)';
        // NOTE: The 'email' column will be NULL for new users by default with this INSERT,
        // unless you add new_email to pendingUserData and pass it here.
        // For simplicity, I'm assuming 'username' is the primary login and 'contact_email' is the separate contact email.
        // If the 'email' column should also contain the new user's contact email, you need to revisit the DB schema and frontend.
        pool.query(sql, [new_username, hashedPassword, new_first_name, new_last_name, new_role, null, new_contact_email], (err, result) => {
            if (err) {
                if (err.code === '23505') { // ER_DUP_ENTRY
                    // This could be a duplicate username OR email.
                    verificationCodes.delete(adminId);
                    return res.status(409).send('Username or Email already exists.');
                }
                console.error('Error creating new user:', err);
                verificationCodes.delete(adminId);
                return res.status(500).send('Error creating new user.');
            }
            verificationCodes.delete(adminId);
            res.status(201).json({ success: true });
        });
    } catch (error) {
        console.error('Error hashing password during user creation:', error);
        verificationCodes.delete(adminId);
        res.status(500).send('Internal server error.');
    }
});

// In-memory store for reset codes
const passwordResetCodes = new Map();

app.post('/api/auth/forgot-password', async (req, res) => {
    // Always send to admin email from .env
    const adminEmail = process.env.EMAIL_USER;
    if (!adminEmail) return res.status(500).send('Admin email not configured.');

    // Generate code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    passwordResetCodes.set(adminEmail, { code, expires: Date.now() + 10 * 60 * 1000 }); // 10 min

    // Send email
    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: adminEmail,
            subject: 'Password Reset Code',
            html: `<p>Your password reset code is: <b>${code}</b></p>`
        });
        res.send('Reset code sent to admin email.');
    } catch (e) {
        res.status(500).send('Failed to send email.');
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    const { code, newPassword } = req.body;
    const adminEmail = process.env.EMAIL_USER;
    const stored = passwordResetCodes.get(adminEmail);
    if (!stored || stored.code !== code || Date.now() > stored.expires) {
        return res.status(400).send('Invalid or expired code.');
    }
    // Update the admin's password (assuming username is 'admin' or similar)
    // You may need to adjust this query to match your admin's username or id
    const hashed = await bcrypt.hash(newPassword, 10);
    pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashed, adminEmail], (err) => {
        if (err) return res.status(500).send('Failed to reset password.');
        passwordResetCodes.delete(adminEmail);
        res.send('Password reset successful!');
    });
});

// GET contact info (public)
app.get('/api/contact-info', (req, res) => {
    const sql = 'SELECT data FROM contact_info LIMIT 1';
    pool.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching contact info:', err);
            return res.status(500).json({ error: 'Failed to fetch contact info.' });
        }
        if (results.rows.length === 0) {
            return res.status(404).json({ error: 'No contact info found.' });
        }
        let data = results.rows[0].data;
        if (typeof data === 'string') {
            try { data = JSON.parse(data); } catch (e) {}
        }
        res.json(data);
    });
});

// PUT contact info (admin only)
app.put('/api/contact-info', authenticateToken, isAdmin, (req, res) => {
    const newData = req.body;
    const sql = 'UPDATE contact_info SET data = $1 WHERE id = 1';
    pool.query(sql, [JSON.stringify(newData)], (err, result) => {
        if (err) {
            console.error('Error updating contact info:', err);
            return res.status(500).json({ error: 'Failed to update contact info.' });
        }
        res.json({ success: true });
    });
});

// --- BRAND PARTNERS API ---

// Get all brand partners
app.get('/api/brand-partners', (req, res) => {
    const sql = 'SELECT * FROM brand_partners ORDER BY created_at DESC';
    pool.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching brand partners:', err);
            return res.status(500).send('Error fetching brand partners');
        }
        res.json(results.rows);
    });
});

// Add a new brand partner (admin only, supports file upload or URL)
app.post('/api/brand-partners', authenticateToken, isAdmin, upload.single('image'), (req, res) => {
    const { name, image_url } = req.body;
    let finalImageUrl = image_url || null;
    if (req.file) {
        finalImageUrl = `/uploads/${req.file.filename}`;
    }
    if (!name || !finalImageUrl) {
        return res.status(400).send('Name and image are required.');
    }
    const sql = 'INSERT INTO brand_partners (name, image_url) VALUES ($1, $2)';
    pool.query(sql, [name, finalImageUrl], (err, result) => {
        if (err) {
            console.error('Error adding brand partner:', err);
            return res.status(500).send('Error adding brand partner');
        }
        res.status(201).json({ id: result.rows[0].id, name, image_url: finalImageUrl });
    });
});

// Delete a brand partner (admin only)
app.delete('/api/brand-partners/:id', authenticateToken, isAdmin, (req, res) => {
    const id = req.params.id;
    const sql = 'DELETE FROM brand_partners WHERE id = $1';
    pool.query(sql, [id], (err, result) => {
        if (err) {
            console.error('Error deleting brand partner:', err);
            return res.status(500).send('Error deleting brand partner');
        }
        if (result.rowCount === 0) {
            return res.status(404).send('Brand partner not found');
        }
        res.send('Brand partner deleted successfully');
    });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

app.post('/api/contact-submissions', (req, res) => {
  const { subject, request, first_name, last_name, email, phone } = req.body;
  const sql = 'INSERT INTO contact_submissions (subject, request, first_name, last_name, email, phone) VALUES ($1, $2, $3, $4, $5, $6)';
  pool.query(sql, [subject, request, first_name, last_name, email, phone], (err, result) => {
    if (err) return res.status(500).json({ success: false, error: 'Error saving submission' });
    res.status(201).json({ success: true });
  });
});

app.get('/api/contact-submissions', (req, res) => {
  pool.query('SELECT * FROM contact_submissions ORDER BY created_at DESC', (err, results) => {
    if (err) return res.status(500).send('Error fetching submissions');
    res.json(results.rows);
  });
});

app.delete('/api/contact-submissions/:id', (req, res) => {
  const id = req.params.id;
  pool.query('DELETE FROM contact_submissions WHERE id = $1', [id], (err, result) => {
    if (err) return res.status(500).json({ success: false, error: 'Error deleting submission' });
    res.json({ success: true });
  });
});

// Delete an inquiry by ID (admin only)
app.delete('/api/inquiries/:id', authenticateToken, (req, res) => {
    const inquiryId = req.params.id;
    const sql = 'DELETE FROM inquiries WHERE id = $1';
    pool.query(sql, [inquiryId], (err, result) => {
        if (err) {
            console.error('Error deleting inquiry:', err);
            return res.status(500).send('Error deleting inquiry');
        }
        if (result.rowCount === 0) {
            return res.status(404).send('Inquiry not found');
        }
        res.send('Inquiry deleted successfully');
    });
});

// Force deployment
