const Sequelize = require('sequelize');
const config = require('../config/config.js'); // Changed from .json to .js
const env = process.env.NODE_ENV || 'development';
const configEnv = config[env];

const sequelize = new Sequelize(configEnv.database, configEnv.username, configEnv.password, configEnv);

const db = {};

db.sequelize = sequelize;
db.Sequelize = Sequelize;

db.Admin = require('./admin')(sequelize, Sequelize.DataTypes);
db.Player = require('./player')(sequelize, Sequelize.DataTypes);
db.Sport = require('./sport')(sequelize, Sequelize.DataTypes);
db.Session = require('./session')(sequelize, Sequelize.DataTypes);
db.Match = require('./match')(sequelize, Sequelize.DataTypes);

module.exports = db;
