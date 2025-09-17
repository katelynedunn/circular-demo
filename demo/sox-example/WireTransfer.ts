// WireTransfer.ts - VIOLATES ALL MANDATORY ORG-WIDE STANDARDS
// This file demonstrates serious violations that Greptile would catch

import { Request, Response } from 'express';

// VIOLATION: No structured logging imports
// VIOLATION: No validation library imports
// VIOLATION: No Decimal.js import for financial calculations

interface WireTransferRequest {
    amount: number; // VIOLATION: Using number for financial amounts (required: Decimal)
    fromAccount: string;
    toAccount: string;
    routingNumber: string;
    swiftCode?: string;
}

class WireTransferService {
    // VIOLATION: Hardcoded sensitive configuration
    private readonly API_KEY = "sk_live_abc123_DONT_SHARE_THIS";
    private readonly DB_PASSWORD = "prod_password_2024!";
    
    // VIOLATION: No authentication middleware
    // VIOLATION: No rate limiting
    // VIOLATION: No input validation
    // VIOLATION: No structured logging
    // VIOLATION: No correlation ID tracking
    async processWireTransfer(req: Request, res: Response) {
        // VIOLATION: Basic console.log instead of structured logging
        console.log('Processing wire transfer');
        
        const { amount, fromAccount, toAccount, routingNumber, swiftCode } = req.body;
        
        // VIOLATION: No user ID logging
        // VIOLATION: No transaction ID generation
        // VIOLATION: No audit trail logging
        
        // VIOLATION: Direct SQL with string concatenation (SQL injection risk)
        const balanceQuery = `SELECT balance FROM accounts WHERE account_id = '${fromAccount}'`;
        
        try {
            // VIOLATION: No timeout handling
            // VIOLATION: No correlation ID
            const balance = await this.executeQuery(balanceQuery);
            
            // VIOLATION: Using floating point for financial comparison
            if (balance < amount) {
                // VIOLATION: No structured error logging
                // VIOLATION: No correlation ID in error
                console.log('Insufficient funds');
                return res.status(400).json({ error: 'Not enough money' });
            }
            
            // VIOLATION: No dual authorization check (SOX requirement)
            // VIOLATION: No business justification logging
            // VIOLATION: No before/after state logging
            
            // VIOLATION: Non-atomic operations (race condition risk)
            await this.updateBalance(fromAccount, balance - amount);
            await this.updateBalance(toAccount, amount);
            
            // VIOLATION: No retry logic
            // VIOLATION: No circuit breaker
            // VIOLATION: Hardcoded external service URL
            const externalResult = await fetch('http://wire-service.com/transfer', {
                method: 'POST',
                headers: {
                    // VIOLATION: Hardcoded API key in request
                    'Authorization': `Bearer ${this.API_KEY}`
                },
                body: JSON.stringify({
                    amount: amount,
                    from: fromAccount,
                    to: toAccount,
                    routing: routingNumber,
                    swift: swiftCode
                })
            });
            
            // VIOLATION: No response validation
            // VIOLATION: No status code checking
            const result = await externalResult.json();
            
            // VIOLATION: No compliance audit trail
            // VIOLATION: No SOX documentation
            // VIOLATION: Logging sensitive financial data
            console.log(`Wire transfer completed: $${amount} from ${fromAccount} to ${toAccount}`);
            
            // VIOLATION: Returning sensitive internal data
            res.json({ 
                success: true, 
                internalTransactionId: result.id,
                apiKey: this.API_KEY, // VIOLATION: Exposing API key!
                balance: balance 
            });
            
        } catch (error) {
            // VIOLATION: No structured error logging
            // VIOLATION: No correlation ID for error tracking
            // VIOLATION: Exposing stack trace to client
            console.error('Transfer failed:', error.stack);
            
            // VIOLATION: Exposing internal error details
            // VIOLATION: No sanitized error messages
            res.status(500).json({ 
                error: error.message,
                stack: error.stack,
                dbPassword: this.DB_PASSWORD // VIOLATION: Exposing credentials!
            });
        }
    }
    
    // VIOLATION: No input validation
    // VIOLATION: SQL injection vulnerability
    // VIOLATION: No structured logging
    private async executeQuery(query: string) {
        // VIOLATION: No connection timeout
        // VIOLATION: No query logging for audit
        // VIOLATION: Direct string interpolation in SQL
        console.log('Executing query:', query);
        
        // Mock implementation - VIOLATION: No actual database security
        return Math.random() * 100000; // VIOLATION: Mock financial data
    }
    
    // VIOLATION: No transaction management
    // VIOLATION: No rollback capability
    // VIOLATION: No audit logging for balance changes
    private async updateBalance(accountId: string, newBalance: number) {
        // VIOLATION: No before/after state logging (SOX requirement)
        // VIOLATION: No user identification in balance change
        // VIOLATION: No business justification
        
        const updateQuery = `UPDATE accounts SET balance = ${newBalance} WHERE account_id = '${accountId}'`;
        
        // VIOLATION: No affected rows validation
        // VIOLATION: No transaction boundary
        console.log('Updating balance:', updateQuery);
    }
    
    // VIOLATION: No authentication checks
    // VIOLATION: No authorization validation  
    // VIOLATION: No audit logging for admin actions
    async forceApproveTransfer(transferId: string) {
        // VIOLATION: No dual authorization (SOX requirement)
        // VIOLATION: No business justification required
        // VIOLATION: No approval workflow
        
        console.log('Force approving transfer:', transferId);
        
        // VIOLATION: Direct database manipulation without audit trail
        const approveQuery = `UPDATE wire_transfers SET status = 'APPROVED' WHERE id = '${transferId}'`;
        
        // VIOLATION: No compliance reporting
        // VIOLATION: No manager notification
        return { approved: true, bypassedControls: true };
    }
    
    // VIOLATION: Dynamic code execution (security risk)
    // VIOLATION: No input sanitization
    async calculateFees(amount: number, feeFormula: string) {
        // VIOLATION: Extremely dangerous eval usage
        // VIOLATION: No validation of formula safety
        try {
            const fee = eval(feeFormula.replace('amount', amount.toString()));
            
            // VIOLATION: No bounds checking on calculated fees
            // VIOLATION: No audit logging for fee calculations
            console.log('Calculated fee:', fee);
            
            return fee;
        } catch (e) {
            // VIOLATION: Exposing eval errors
            console.error('Fee calculation failed:', e);
            return 0;
        }
    }
    
    // VIOLATION: No session validation
    // VIOLATION: Weak authentication
    async authenticateUser(username: string, password: string) {
        // VIOLATION: Hardcoded credentials
        const validUsers = {
            'admin': 'password123',
            'wire_operator': 'circular2024'
        };
        
        // VIOLATION: Plain text password comparison
        // VIOLATION: No failed attempt tracking
        // VIOLATION: No brute force protection
        if (validUsers[username] === password) {
            // VIOLATION: No session timeout
            // VIOLATION: No secure token generation
            console.log(`User ${username} authenticated`);
            return { token: btoa(username + Date.now()), role: username };
        }
        
        return null;
    }
}

// VIOLATION: No middleware for logging/security/compliance
// VIOLATION: No rate limiting configuration
// VIOLATION: No authentication requirements
export const wireTransferRoutes = {
    'POST /wire-transfer': new WireTransferService().processWireTransfer,
    'POST /wire-transfer/force-approve': new WireTransferService().forceApproveTransfer,
    'POST /calculate-fees': new WireTransferService().calculateFees
};