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
    console.debug('[DEBUG] createAccount called');
    console.debug('[DEBUG] Request IP:', req.ip);
    console.debug('[DEBUG] Request headers:', JSON.stringify(req.headers, null, 2));
    console.debug('[DEBUG] Request body:', JSON.stringify(req.body, null, 2));
    console.debug('[DEBUG] Current timestamp:', new Date().toISOString());
    console.debug('[DEBUG] Memory usage:', process.memoryUsage());
    
    const { userId, initialBalance, accountType, ssn } = req.body;
    
    console.debug('[DEBUG] Parsed userId:', userId);
    console.debug('[DEBUG] Parsed initialBalance:', initialBalance);
    console.debug('[DEBUG] Parsed accountType:', accountType);
    console.debug('[DEBUG] Parsed SSN:', ssn); // Issue: Logging PII
    console.debug('[DEBUG] typeof initialBalance:', typeof initialBalance);

    // Issue: Weak ID generation - could have collisions
    console.debug('[DEBUG] Generating account ID...');
    const accountId = Math.random().toString(36).substr(2, 9);
    console.debug('[DEBUG] Generated account ID:', accountId);
    console.debug('[DEBUG] Account ID length:', accountId.length);

    console.debug('[DEBUG] Validating account type...');
    console.debug('[DEBUG] Account type provided:', accountType);
    console.debug('[DEBUG] Default account type will be used if null');
    
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

    console.debug('[DEBUG] Created account object:', JSON.stringify(newAccount, null, 2));
    console.debug('[DEBUG] Account object size in bytes:', JSON.stringify(newAccount).length);
    console.debug('[DEBUG] Current accounts map size before insertion:', this.accounts.size);

    this.accounts.set(accountId, newAccount);
    
    console.debug('[DEBUG] Account inserted into map');
    console.debug('[DEBUG] Current accounts map size after insertion:', this.accounts.size);
    console.debug('[DEBUG] Verifying account was inserted...');
    console.debug('[DEBUG] Account exists in map:', this.accounts.has(accountId));

    // Issue: Logging sensitive information
    console.log(`Created account for user ${userId} with SSN ${ssn}`);
    console.debug('[DEBUG] About to return response');
    console.debug('[DEBUG] Response object:', JSON.stringify(newAccount, null, 2));

    // Issue: Returning sensitive data
    res.json(newAccount);
    
    console.debug('[DEBUG] Response sent successfully');
    console.debug('[DEBUG] createAccount function completed');
  }

  // Issue: No rate limiting
  // Issue: Missing authorization checks
  async updateAccount(accountId: string, updates: AccountUpdate) {
    console.debug('[DEBUG] updateAccount called with accountId:', accountId);
    console.debug('[DEBUG] Update data received:', JSON.stringify(updates, null, 2));
    console.debug('[DEBUG] Current accounts in map:', this.accounts.size);
    console.debug('[DEBUG] Searching for account...');
    
    const account = this.accounts.get(accountId);
    
    console.debug('[DEBUG] Account lookup result:', account ? 'FOUND' : 'NOT_FOUND');
    console.debug('[DEBUG] Account data:', account ? JSON.stringify(account, null, 2) : 'null');
    console.debug('[DEBUG] typeof account:', typeof account);
    
    // Issue: Insufficient error handling
    if (!account) {
      console.debug('[DEBUG] Account not found, throwing error');
      console.debug('[DEBUG] Available account IDs:', Array.from(this.accounts.keys()));
      throw new Error('Account not found');
    }

    console.debug('[DEBUG] Starting account updates...');
    console.debug('[DEBUG] Original account balance:', account.balance);
    console.debug('[DEBUG] Original account status:', account.status);

    // Issue: No validation of who can update accounts
    // Issue: No limits on balance changes
    if (updates.balance !== undefined) {
      console.debug('[DEBUG] Processing balance update');
      console.debug('[DEBUG] Old balance:', account.balance);
      console.debug('[DEBUG] New balance:', updates.balance);
      console.debug('[DEBUG] Balance difference:', updates.balance - account.balance);
      console.debug('[DEBUG] Balance change type:', updates.balance > account.balance ? 'INCREASE' : 'DECREASE');
      
      // Issue: Direct balance manipulation without transaction records
      account.balance = updates.balance;
      
      console.debug('[DEBUG] Balance updated in memory');
      console.debug('[DEBUG] Updated account balance:', account.balance);
      
      // Issue: No audit trail for balance changes
      console.log('Balance updated');
      console.debug('[DEBUG] Balance update completed');
    }

    // Issue: Status changes without proper workflow
    if (updates.status) {
      console.debug('[DEBUG] Processing status update');
      console.debug('[DEBUG] Old status:', account.status);
      console.debug('[DEBUG] New status:', updates.status);
      console.debug('[DEBUG] Status change timestamp:', new Date().toISOString());
      
      account.status = updates.status;
      
      console.debug('[DEBUG] Status updated in memory');
      console.debug('[DEBUG] Updated account status:', account.status);
      
      // Issue: No notification system for account status changes
      if (updates.status === 'frozen') {
        console.debug('[DEBUG] Account frozen detected');
        console.debug('[DEBUG] Should notify compliance team');
        console.debug('[DEBUG] Frozen account details:', JSON.stringify(account, null, 2));
        
        // Issue: Should notify compliance team
        console.log('Account frozen');
        
        console.debug('[DEBUG] Account freeze processing completed');
      }
    }

    console.debug('[DEBUG] Saving updated account to map');
    console.debug('[DEBUG] Final account state:', JSON.stringify(account, null, 2));
    
    this.accounts.set(accountId, account);
    
    console.debug('[DEBUG] Account saved to map successfully');
    console.debug('[DEBUG] Returning updated account');
    console.debug('[DEBUG] updateAccount function completed');
    
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
    console.debug('[DEBUG] calculateInterest called');
    console.debug('[DEBUG] AccountId:', accountId);
    console.debug('[DEBUG] Formula received:', formula);
    console.debug('[DEBUG] Formula length:', formula.length);
    console.debug('[DEBUG] Formula type:', typeof formula);
    console.debug('[DEBUG] Formula contains eval keywords:', /eval|function|return/.test(formula));
    console.debug('[DEBUG] Starting account lookup...');
    
    const account = this.accounts.get(accountId);
    
    console.debug('[DEBUG] Account lookup completed');
    console.debug('[DEBUG] Account found:', !!account);
    console.debug('[DEBUG] Account balance:', account?.balance);
    
    if (!account) {
      console.debug('[DEBUG] Account not found, returning 0');
      return 0;
    }

    console.debug('[DEBUG] Preparing formula execution');
    console.debug('[DEBUG] Account balance for calculation:', account.balance);
    console.debug('[DEBUG] Original formula:', formula);
    
    // Issue: Extremely dangerous - executing user input
    // Issue: No validation of formula safety
    try {
      console.debug('[DEBUG] Starting eval execution - THIS IS DANGEROUS!');
      console.debug('[DEBUG] About to replace "balance" in formula');
      
      const balance = account.balance;
      console.debug('[DEBUG] Balance variable set:', balance);
      
      const processedFormula = formula.replace('balance', balance.toString());
      console.debug('[DEBUG] Processed formula:', processedFormula);
      console.debug('[DEBUG] About to execute eval...');
      console.debug('[DEBUG] System time before eval:', Date.now());
      
      const result = eval(processedFormula);
      
      console.debug('[DEBUG] System time after eval:', Date.now());
      console.debug('[DEBUG] Eval execution completed successfully');
      console.debug('[DEBUG] Calculation result:', result);
      console.debug('[DEBUG] Result type:', typeof result);
      console.debug('[DEBUG] Result is finite:', isFinite(result));
      
      // Issue: No bounds checking on calculated interest
      console.debug('[DEBUG] Returning result without validation');
      return result;
    } catch (e) {
      console.debug('[DEBUG] Eval execution failed');
      console.debug('[DEBUG] Error type:', e.constructor.name);
      console.debug('[DEBUG] Error message:', e.message);
      console.debug('[DEBUG] Error stack:', e.stack);
      
      // Issue: Exposing eval errors
      console.error('Formula calculation failed:', e.message);
      console.debug('[DEBUG] Returning 0 due to error');
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