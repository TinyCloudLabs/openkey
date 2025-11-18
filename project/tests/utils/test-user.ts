export class TestUser {
  public email: string;
  public password?: string;
  
  constructor() {
    // Generate unique email for each test
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(7);
    this.email = `test-${timestamp}-${random}@openkey.test`;
  }
  
  static generateTestEmail(): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(7);
    return `test-${timestamp}-${random}@openkey.test`;
  }
}