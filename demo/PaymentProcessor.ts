// PaymentProcessor.ts
import { Request, Response } from 'express';
import { Database } from '../database/connection';

interface PaymentRequest {
  amount: number; // Should use Decimal type for financial calculations
  fromAccount: string;
  toAccount: string;
  userId?: string; // Should be required for audit trail
}

class PaymentProcessor {
  private db: Database;

  constructor(db: Database) {
    this.db = db;
  }

  // Missing authentication middleware check
  // Missing input validation
  // No audit logging
  async processPayment(req: Request, res: Response) {
    const { amount, fromAccount, toAccount, userId } = req.body;

    // Issue: No input validation for financial amounts
    // Issue: Using floating point for money calculations
    if (amount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    try {
      // Issue: No transaction management
      // Issue: Missing audit trail logging
      const fromBalance = await this.db.getAccountBalance(fromAccount);
      
      // Issue: No proper error handling if account doesn't exist
      if (fromBalance < amount) {
        return res.status(400).json({ error: 'Insufficient funds' });
      }

      // Issue: Race condition - no atomic transaction
      await this.db.updateBalance(fromAccount, fromBalance - amount);
      await this.db.updateBalance(toAccount, await this.db.getAccountBalance(toAccount) + amount);

      // Issue: Missing SOX compliance logging
      // Issue: No transaction ID generated for audit trail
      console.log('Payment processed'); // Too basic logging

      res.json({ success: true });
    } catch (error) {
      // Issue: Logging sensitive error details
      // Issue: No proper error classification
      console.error('Payment failed:', error);
      res.status(500).json({ error: error.message }); // Exposing internal errors
    }
  }

  // Issue: No rate limiting
  // Issue: Missing authentication checks
  async getAccountBalance(accountId: string) {
    // Issue: SQL injection vulnerability
    const query = `SELECT balance FROM accounts WHERE id = '${accountId}'`;
    const result = await this.db.raw(query);
    return result[0]?.balance;
  }

  // Issue: No input validation
  // Issue: Missing authorization checks
  async transferToExternalBank(amount: number, externalAccount: string) {
    // Issue: No circuit breaker for external services
    // Issue: No timeout handling
    // Issue: Hardcoded API URL
    const response = await fetch('https://api.externalbank.com/transfer', {
      method: 'POST',
      body: JSON.stringify({ amount, account: externalAccount })
    });

    // Issue: No proper error handling
    return response.json();
  }
}

// Issue: No proper error boundaries
// Issue: Missing middleware for compliance logging
export const paymentRouter = (db: Database) => {
  const processor = new PaymentProcessor(db);
  
  // Issue: No authentication middleware
  // Issue: No rate limiting
  return {
    '/payment': processor.processPayment.bind(processor),
    '/balance/:id': processor.getAccountBalance.bind(processor)
  };
};