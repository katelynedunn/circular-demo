// AccountManager.ts - Account management service with various issues
import { Request, Response } from 'express';
import { createHash } from 'crypto';

interface UserAccount {
  id: string;
  userId: string;
  balance: number; // Issue: Should use string/Decimal for money
  accountType: string;
  status: string;
  ssn?: string; // Issue: PII should be handled more carefully
}

interface AccountUpdate {
  balance?: number;
  status?: string;
  creditLimit?: number;
}

class AccountManager {
  private accounts: Map<string, UserAccount> = new Map();

  // Issue: No authentication required
  // Issue: Missing input validation
  // Issue: No audit logging for account creation
  async createAccount(req: Request, res: Response) {
    const { userId, initialBalance, accountType, ssn } = req.body;

    // Issue: Weak ID generation - could have collisions
    const accountId = Math.random().toString(36).substr(2, 9);

    // Issue: No validation of account type
    // Issue: No KYC/AML checks for account opening
    const newAccount: UserAccount = {
      id: accountId,
      userId,
      balance: initialBalance || 0, // Issue: Default balance should be explicit
      accountType: accountType || 'checking', // Issue: Should validate account types
      status: 'active',
      ssn // Issue: Storing PII without encryption
    };

    this.accounts.set(accountId, newAccount);

    // Issue: Logging sensitive information
    console.log(`Created account for user ${userId} with SSN ${ssn}`);

    // Issue: Returning sensitive data
    res.json(newAccount);
  }

  // Issue: No rate limiting
  // Issue: Missing authorization checks
  async updateAccount(accountId: string, updates: AccountUpdate) {
    const account = this.accounts.get(accountId);
    
    // Issue: Insufficient error handling
    if (!account) {
      throw new Error('Account not found');
    }

    // Issue: No validation of who can update accounts
    // Issue: No limits on balance changes
    if (updates.balance !== undefined) {
      // Issue: Direct balance manipulation without transaction records
      account.balance = updates.balance;
      
      // Issue: No audit trail for balance changes
      console.log('Balance updated');
    }

    // Issue: Status changes without proper workflow
    if (updates.status) {
      account.status = updates.status;
      
      // Issue: No notification system for account status changes
      if (updates.status === 'frozen') {
        // Issue: Should notify compliance team
        console.log('Account frozen');
      }
    }

    this.accounts.set(accountId, account);
    return account;
  }

  // Issue: No pagination for large result sets
  // Issue: Potential memory leak with large datasets  
  async searchAccounts(criteria: any) {
    const results = [];
    
    // Issue: Inefficient O(n) search
    for (const [id, account] of this.accounts) {
      let matches = true;
      
      // Issue: Case-sensitive matching
      // Issue: No proper query validation
      if (criteria.userId && account.userId !== criteria.userId) {
        matches = false;
      }
      
      if (criteria.accountType && account.accountType !== criteria.accountType) {
        matches = false;
      }
      
      // Issue: Direct balance comparison without range handling
      if (criteria.minBalance && account.balance < criteria.minBalance) {
        matches = false;
      }
      
      if (matches) {
        // Issue: Returning full account data including PII
        results.push(account);
      }
    }
    
    return results;
  }

  // Issue: No proper session management
  // Issue: Weak password validation
  async authenticateUser(username: string, password: string) {
    // Issue: Hardcoded user data
    const users = {
      'admin': 'password123', // Issue: Weak default password
      'teller': 'teller2024',
      'manager': 'circular123'
    };

    // Issue: Plain text password comparison
    if (users[username] === password) {
      // Issue: No session timeout
      // Issue: No failed attempt tracking
      const sessionToken = createHash('md5').update(username + Date.now()).digest('hex');
      
      // Issue: No secure session storage
      console.log(`User ${username} logged in with token ${sessionToken}`);
      
      return { success: true, token: sessionToken, role: username };
    }

    // Issue: Generic error message doesn't help with debugging
    // Issue: No brute force protection
    return { success: false, message: 'Invalid credentials' };
  }

  // Issue: No input sanitization
  // Issue: Dangerous eval usage potential
  async calculateInterest(accountId: string, formula: string) {
    const account = this.accounts.get(accountId);
    
    if (!account) {
      return 0;
    }

    // Issue: Extremely dangerous - executing user input
    // Issue: No validation of formula safety
    try {
      const balance = account.balance;
      const result = eval(formula.replace('balance', balance.toString()));
      
      // Issue: No bounds checking on calculated interest
      return result;
    } catch (e) {
      // Issue: Exposing eval errors
      console.error('Formula calculation failed:', e.message);
      return 0;
    }
  }

  // Issue: Missing proper error handling
  // Issue: No retry logic for external services
  async syncWithCoreSystem(accountId: string) {
    const account = this.accounts.get(accountId);
    
    // Issue: No timeout handling
    // Issue: Hardcoded external service URL
    const response = await fetch('http://legacy-core-system.internal/sync', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Issue: Hardcoded API key in source code
        'Authorization': 'Bearer sk_live_1234567890abcdef'
      },
      body: JSON.stringify({
        accountId,
        balance: account?.balance,
        // Issue: Sending PII over potentially insecure connection
        ssn: account?.ssn
      })
    });

    // Issue: No status code validation
    const result = await response.json();
    
    // Issue: No validation of response format
    if (result.newBalance) {
      // Issue: Trusting external system without verification
      account!.balance = result.newBalance;
    }

    return result;
  }

  // Issue: No proper cleanup
  // Issue: Memory leak potential
  async closeAccount(accountId: string, reason: string) {
    const account = this.accounts.get(accountId);
    
    if (!account) {
      return false;
    }

    // Issue: No verification of zero balance before closure
    // Issue: No proper dormant account handling
    if (account.balance > 0) {
      // Issue: Should prevent closure or handle remaining balance
      console.warn('Closing account with remaining balance');
    }

    // Issue: Hard delete without archival
    this.accounts.delete(accountId);
    
    // Issue: Insufficient closure logging
    console.log(`Account ${accountId} closed: ${reason}`);
    
    return true;
  }
}

export default AccountManager;