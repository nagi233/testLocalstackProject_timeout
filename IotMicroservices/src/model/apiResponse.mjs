export class ApiResponse {
  constructor() {
    this.succeed = false;
    this.result = "";
    this.message = "";
    this.error = "";
  }

  toString() {
    return JSON.stringify(this);
  }
}
