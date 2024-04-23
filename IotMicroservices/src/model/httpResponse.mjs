export class HttpResponse {
  constructor() {
    this.statusCode = 200;
    this.body = "{}";
    this.headers = {
      "Access-Control-Allow-Headers":
        "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "OPTIONS,POST,GET",
    };
    this.isBase64Encoded = false;
  }
}
