import { Sequelize, DataTypes, Model } from 'sequelize';

export class Role extends Model {}

export const initRoleModel = (sequelize: Sequelize) => {
  Role.init({
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    level: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
  }, {
    sequelize,
    modelName: 'Role',
    tableName: 'roles',
    timestamps: false,
  });

  return Role;
};
