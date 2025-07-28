import { Sequelize, DataTypes, Model, UUIDV4 } from 'sequelize';

export class SystemUserSecret extends Model {}

export const initSystemUserSecretModel = (sequelize: Sequelize) => {
  SystemUserSecret.init({
    id: {
      type: DataTypes.UUID,
      defaultValue: UUIDV4,
      primaryKey: true,
    },
    user_id: {
      type: DataTypes.UUID,
      allowNull: false,
    },
    secret_key: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    description: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    created_at: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW,
    },
    updated_at: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW,
    },
  }, {
    sequelize,
    modelName: 'SystemUserSecret',
    tableName: 'system_user_secret',
    timestamps: false,
  });

  return SystemUserSecret;
};
