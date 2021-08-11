import {
  IUserPersistance,
  IFieldMap,
  IUser,
  FindAuthenticationStrategyResponse,
} from "@kaviar/security-bundle";
import { Collection, Behaviors } from "@kaviar/mongo-bundle";
import jwtDecode from "jwt-decode";

export class UsersCollection<T extends IUser>
  extends Collection<T>
  implements IUserPersistance {

  async insertUser(data: any): Promise<any> {
    // await insert user via AWS Cognito
    return ""
  }

  async updateUser(userId: any, data: any): Promise<void> {
    // await update user via AWS Cognito
  }

  async deleteUser(userId: any): Promise<void> {
    // await delete user via AWS Cognito
  }

  async findUser(filters: any, projection?: IFieldMap): Promise<IUser> {
    let data: any = jwtDecode(filters.userId)
    return {
      _id: data.username,
      isEnabled: !!data,
      createdAt: new Date(data.iat),
      lastLoginAt: new Date(),
      roles: []
    }
  }

  async findUserById(userId: any, projection?: IFieldMap): Promise<IUser> {
    let data: any = jwtDecode(userId)

    return {
      _id: data.username,
      isEnabled: !!data,
      createdAt: new Date(data.iat),
      lastLoginAt: new Date(),
      roles: data["cognito:groups"]
    }
  }

  async updateAuthenticationStrategyData<T = any>(
    userId: any,
    methodName: string,
    data: null | Partial<T>
  ): Promise<void> {
    // TODO: more efficiently via $set directly
    // const authMethod = await this.getAuthenticationStrategyData(
    //   userId,
    //   methodName
    // );

    // const current = authMethod ? authMethod : {};

    // Object.assign(current, data);

    // await this.updateOne({ _id: userId }, {
    //   $set: {
    //     [methodName]: current,
    //   },
    // } as any);

  }

  async findThroughAuthenticationStrategy<T = any>(
    strategyName: string,
    filters: any,
    fields?: IFieldMap
  ): Promise<FindAuthenticationStrategyResponse<T> | null> {
    // const methodFilters = {};
    // for (const key in filters) {
    //   methodFilters[`${strategyName}.${key}`] = filters[key];
    // }

    // // TODO: projection
    // const result = await this.findOne(methodFilters);

    // if (!result) {
    //   return null;
    // }

    // return {
    //   userId: result._id,
    //   strategy: result[strategyName],
    // };
    return null;
  }

  async getAuthenticationStrategyData<T = any>(
    userId: any,
    strategyName: string
  ): Promise<T> {
    // TODO: implement projection
    // const user = await this.findOne(
    //   { _id: userId },
    //   {
    //     projection: {
    //       [strategyName]: 1,
    //     },
    //   }
    // );

    // return user ? user[strategyName] : null;
    return null;
  }

  async removeAuthenticationStrategyData(
    userId: any,
    methodName: string
  ): Promise<void> {
    // await this.updateOne({ _id: userId }, {
    //   $unset: {
    //     [methodName]: 1,
    //   },
    // } as any);
  }
}
