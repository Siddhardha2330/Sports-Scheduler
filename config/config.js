require('dotenv').config();

module.exports = {
  development: {
    username: 'postgres',
    password: '1234',
    database: 'postgres4',
    host: '127.0.0.1',
    dialect: 'postgres',
  },
  test: {
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD || '1234',
    database: process.env.DB_DATABASE || 'postgres5',
    host: process.env.DB_HOST || '127.0.0.1',
    dialect: process.env.DB_DIALECT || 'postgres',
  },
  production: {
    username: 'postgres',
    password: '1234',
    database: 'postgres6',
    host: '127.0.0.1',
    dialect: 'postgres',
  },
};
