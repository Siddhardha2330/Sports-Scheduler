'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class Match extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
    }
  }
  Match.init({
    creator: DataTypes.STRING,
    sport: DataTypes.STRING,
    place: DataTypes.STRING,
    player:DataTypes.STRING ,
    date: DataTypes.DATE,
    begintime: DataTypes.TIME,
    endtime: DataTypes.TIME,
    playerscount: DataTypes.INTEGER,
    venue: DataTypes.STRING,
    reason: DataTypes.STRING
    
    
  }, {
    sequelize,
    modelName: 'Match',
  });
  return Match;
};