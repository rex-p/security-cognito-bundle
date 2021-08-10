import {
  IUserPersistance,
  IFieldMap,
  IUser,
  FindAuthenticationStrategyResponse,
} from "@kaviar/security-bundle";
import { Collection, Behaviors } from "@kaviar/mongo-bundle";

export class UsersCollection<T extends IUser>
  extends Collection<T>
  implements IUserPersistance {
  static collectionName = "users";

  static behaviors = [Behaviors.Timestampable()];

  async insertUser(data: any): Promise<any> {
    const result = await this.insertOne(data);

    return result.insertedId;
  }

  async updateUser(userId: any, data: any): Promise<void> {
    await this.updateOne(
      {
        _id: userId,
      },
      {
        $set: data,
      }
    );
  }

  async deleteUser(userId: any): Promise<void> {
    await this.deleteOne({ _id: userId });
  }

  async findUser(filters: any, projection?: IFieldMap): Promise<IUser> {
    const data = {
      "origin_jti": "b03d2a98-3984-4e9d-8de8-27c8ccea3d44",
      "sub": "8123d38b-ce05-450c-91f2-d406ad073a74",
      "event_id": "3e5a0d48-bdcf-4cc7-bee7-c1e3dd74b18b",
      "token_use": "access",
      "scope": "aws.cognito.signin.user.admin",
      "auth_time": 1628504469,
      "iss": "https://cognito-idp.ap-south-1.amazonaws.com/ap-south-1_rz9ATi0PU",
      "exp": 1628508069,
      "iat": 1628504469,
      "jti": "995bc83c-206a-4fac-966e-82591ebf7dbe",
      "client_id": "33hi099rqt9map6utf2iraribg",
      "username": "ray"
    }
  
      return {
        _id: data.username,
        isEnabled: !!data,
        createdAt: new Date(data.iat),
        lastLoginAt: new Date(),
        roles: []
      }
  }

  async findUserById(userId: any, projection?: IFieldMap): Promise<IUser> {
   const data = {
    "origin_jti": "b03d2a98-3984-4e9d-8de8-27c8ccea3d44",
    "sub": "8123d38b-ce05-450c-91f2-d406ad073a74",
    "event_id": "3e5a0d48-bdcf-4cc7-bee7-c1e3dd74b18b",
    "token_use": "access",
    "scope": "aws.cognito.signin.user.admin",
    "auth_time": 1628504469,
    "iss": "https://cognito-idp.ap-south-1.amazonaws.com/ap-south-1_rz9ATi0PU",
    "exp": 1628508069,
    "iat": 1628504469,
    "jti": "995bc83c-206a-4fac-966e-82591ebf7dbe",
    "client_id": "33hi099rqt9map6utf2iraribg",
    "username": "ray"
  }

    return {
      _id: data.username,
      isEnabled: !!data,
      createdAt: new Date(data.iat),
      lastLoginAt: new Date(),
      roles: []
    }
  }

  async updateAuthenticationStrategyData<T = any>(
    userId: any,
    methodName: string,
    data: null | Partial<T>
  ): Promise<void> {
    // TODO: more efficiently via $set directly
    const authMethod = await this.getAuthenticationStrategyData(
      userId,
      methodName
    );

    const current = authMethod ? authMethod : {};

    Object.assign(current, data);

    await this.updateOne({ _id: userId }, {
      $set: {
        [methodName]: current,
      },
    } as any);
  }

  async findThroughAuthenticationStrategy<T = any>(
    strategyName: string,
    filters: any,
    fields?: IFieldMap
  ): Promise<FindAuthenticationStrategyResponse<T> | null> {
    const methodFilters = {};
    for (const key in filters) {
      methodFilters[`${strategyName}.${key}`] = filters[key];
    }

    // TODO: projection
    const result = await this.findOne(methodFilters);

    if (!result) {
      return null;
    }

    return {
      userId: result._id,
      strategy: result[strategyName],
    };
  }

  async getAuthenticationStrategyData<T = any>(
    userId: any,
    strategyName: string
  ): Promise<T> {
    // TODO: implement projection
    const user = await this.findOne(
      { _id: userId },
      {
        projection: {
          [strategyName]: 1,
        },
      }
    );

    return user ? user[strategyName] : null;
  }

  async removeAuthenticationStrategyData(
    userId: any,
    methodName: string
  ): Promise<void> {
    await this.updateOne({ _id: userId }, {
      $unset: {
        [methodName]: 1,
      },
    } as any);
  }
}
