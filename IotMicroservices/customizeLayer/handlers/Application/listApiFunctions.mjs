import { HttpResponse, ApiResponse } from "../../../src/model/index.mjs";

export const listApiFunctionsHandler = async (event, context) => {
  let httpResponse = new HttpResponse();
  let apiResponse = new ApiResponse();

  try {
    
    let refactResponse = [];

    apiResponse.succeed = result.succeed;
    apiResponse.result = refactResponse;
    apiResponse.message = result.message;
    httpResponse.body = apiResponse.toString();
    utility.log("succeed", httpResponse);
  } catch (err) {
    console.error(err);
    apiResponse.succeed = false;
    apiResponse.message = '内部エラーが発生しました';
    apiResponse.error = 'InternalServerError';
    httpResponse.body = apiResponse.toString();
    console.error("Error", httpResponse);
  } finally {
    return httpResponse;
  }
};
