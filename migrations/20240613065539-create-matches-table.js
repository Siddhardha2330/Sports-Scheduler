'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up (queryInterface, Sequelize) {
    /**
     * Add altering commands here.
     *
     * Example:
     * await queryInterface.createTable('users', { id: Sequelize.INTEGER });
     */
    await queryInterface.createTable('matches', {
      id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: Sequelize.INTEGER
      },
      creator: {
        type: Sequelize.STRING
      },
      player: {
        type: Sequelize.STRING,
        allowNull: false
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

  async down (queryInterface, Sequelize) {
    /**
     * Add reverting commands here.
     *
     * Example:
     * await queryInterface.dropTable('users');
     */
    await queryInterface.dropTable('matches');
  }
};
