'use strict';
/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('sessions', {
      id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: Sequelize.INTEGER
      },
      creator: {
        type: Sequelize.STRING
      },
      sport: {
        type: Sequelize.STRING
      },
      place: {
        type: Sequelize.STRING
      },
      date: {
        type: Sequelize.DATE
      },
      begintime: {
        type: Sequelize.TIME
      },
      endtime: {
        type: Sequelize.TIME
      },
      playerscount: {
        type: Sequelize.INTEGER
      },
      venue: {
        type: Sequelize.STRING
      },
      reason: {
        type: Sequelize.STRING
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE
      }
    });
  },
  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('sessions');
  }
};