// TransactionService.kt - Transaction processing service with various issues
package com.circular.transactions

import java.math.BigDecimal
import java.time.LocalDateTime
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.*
import java.util.*

// Issue: Missing validation annotations
// Issue: Mutable data class properties
data class Transaction(
    var id: String = "",
    var fromAccountId: String = "",
    var toAccountId: String = "",
    var amount: BigDecimal = BigDecimal.ZERO,
    var type: String = "", // Issue: Should use enum
    var status: String = "PENDING", // Issue: Should use sealed class
    var timestamp: LocalDateTime = LocalDateTime.now(),
    var description: String? = null,
    var metadata: MutableMap<String, Any> = mutableMapOf() // Issue: Unsafe type
)

// Issue: Missing proper configuration management
object TransactionConfig {
    const val MAX_DAILY_LIMIT = 50000.00 // Issue: Hardcoded limits
    const val HIGH_RISK_THRESHOLD = 10000.00
    val BLOCKED_COUNTRIES = listOf("XX", "YY") // Issue: Hardcoded compliance data
    const val EXTERNAL_SERVICE_TIMEOUT = 5000L
}

class TransactionService {
    // Issue: Using mutable concurrent collection without proper synchronization
    private val transactions = ConcurrentHashMap<String, Transaction>()
    private val dailyLimits = ConcurrentHashMap<String, BigDecimal>()
    
    // Issue: Global scope usage instead of structured concurrency
    private val scope = GlobalScope

    // Issue: No proper input validation
    // Issue: Missing authentication context
    suspend fun createTransaction(
        fromAccountId: String,
        toAccountId: String,
        amount: BigDecimal,
        description: String?
    ): String {
        
        // Issue: Weak ID generation
        val transactionId = UUID.randomUUID().toString()
        
        // Issue: No amount validation
        if (amount <= BigDecimal.ZERO) {
            // Issue: Generic exception, no specific error types
            throw RuntimeException("Invalid amount")
        }
        
        // Issue: No account validation
        // Issue: Same account transfer not blocked
        if (fromAccountId == toAccountId) {
            println("Warning: Same account transfer detected") // Issue: Basic logging
        }

        val transaction = Transaction(
            id = transactionId,
            fromAccountId = fromAccountId,
            toAccountId = toAccountId,
            amount = amount,
            type = "TRANSFER", // Issue: Hardcoded type
            description = description
        )

        // Issue: No duplicate transaction checking
        transactions[transactionId] = transaction

        // Issue: Fire-and-forget coroutine
        scope.launch {
            processTransaction(transactionId)
        }

        return transactionId
    }

    // Issue: No proper error handling strategy
    // Issue: No timeout handling
    private suspend fun processTransaction(transactionId: String) {
        val transaction = transactions[transactionId] ?: return

        try {
            // Issue: No retry logic
            // Issue: No circuit breaker
            val riskScore = checkRiskScore(transaction)
            
            // Issue: Magic number comparison
            if (riskScore > 0.8) {
                transaction.status = "BLOCKED"
                // Issue: No notification to compliance team
                println("High risk transaction blocked: $transactionId")
                return
            }

            // Issue: No daily limit checking with proper locking
            if (!checkDailyLimit(transaction.fromAccountId, transaction.amount)) {
                transaction.status = "LIMIT_EXCEEDED"
                return
            }

            // Issue: No atomic transaction management
            val fromBalance = getAccountBalance(transaction.fromAccountId)
            if (fromBalance < transaction.amount) {
                transaction.status = "INSUFFICIENT_FUNDS"
                return
            }

            // Issue: Race condition - no proper locking
            updateAccountBalance(transaction.fromAccountId, fromBalance - transaction.amount)
            updateAccountBalance(transaction.toAccountId, transaction.amount)
            
            transaction.status = "COMPLETED"
            transaction.metadata["completedAt"] = LocalDateTime.now()
            
            // Issue: No proper audit logging
            println("Transaction completed: ${transaction.id}")
            
        } catch (e: Exception) {
            // Issue: Generic exception handling
            transaction.status = "FAILED"
            transaction.metadata["error"] = e.message ?: "Unknown error"
            
            // Issue: No proper error logging or alerting
            e.printStackTrace()
        }
    }

    // Issue: No input validation
    // Issue: Blocking external service call
    private suspend fun checkRiskScore(transaction: Transaction): Double {
        // Issue: Hardcoded URL
        // Issue: No proper HTTP client configuration
        delay(100) // Simulating external service call
        
        // Issue: No error handling for external service failure
        // Issue: No fallback strategy
        
        // Simulated risk calculation with issues
        var riskScore = 0.0
        
        // Issue: String comparison for amount (should be BigDecimal)
        if (transaction.amount.toDouble() > TransactionConfig.HIGH_RISK_THRESHOLD) {
            riskScore += 0.3
        }
        
        // Issue: No proper null handling
        if (transaction.description?.contains("urgent", ignoreCase = true) == true) {
            riskScore += 0.2
        }
        
        // Issue: No country validation implementation
        // Just returning mock score
        return riskScore + (0..5).random() * 0.1
    }

    // Issue: Race condition in limit checking
    // Issue: No proper persistence of limits
    private fun checkDailyLimit(accountId: String, amount: BigDecimal): Boolean {
        val currentTotal = dailyLimits.getOrDefault(accountId, BigDecimal.ZERO)
        val newTotal = currentTotal + amount
        
        // Issue: Non-atomic check-then-act
        if (newTotal > BigDecimal(TransactionConfig.MAX_DAILY_LIMIT)) {
            return false
        }
        
        // Issue: Race condition here - another thread could modify between check and update
        dailyLimits[accountId] = newTotal
        return true
    }

    // Issue: Mock implementation without actual database
    // Issue: No error handling
    private suspend fun getAccountBalance(accountId: String): BigDecimal {
        // Issue: Random delay simulating database call
        delay((50..200).random().toLong())
        
        // Mock balance - Issue: Should be from actual database
        return BigDecimal("10000.00")
    }

    // Issue: No transaction management
    // Issue: Mock implementation
    private suspend fun updateAccountBalance(accountId: String, newBalance: BigDecimal) {
        delay((30..100).random().toLong())
        // Issue: No actual persistence
        println("Updated balance for $accountId: $newBalance")
    }

    // Issue: No proper pagination
    // Issue: No access control
    fun getTransactionHistory(
        accountId: String?,
        startDate: LocalDateTime?,
        endDate: LocalDateTime?
    ): List<Transaction> {
        
        // Issue: Inefficient filtering
        // Issue: No limit on result size
        return transactions.values.filter { transaction ->
            var matches = true
            
            // Issue: No null safety in filtering
            if (accountId != null) {
                matches = matches && (transaction.fromAccountId == accountId || 
                                    transaction.toAccountId == accountId)
            }
            
            // Issue: No proper date range validation
            if (startDate != null && transaction.timestamp.isBefore(startDate)) {
                matches = false
            }
            
            if (endDate != null && transaction.timestamp.isAfter(endDate)) {
                matches = false
            }
            
            matches
        }.toList() // Issue: Could return huge lists
    }

    // Issue: No proper cleanup mechanism
    // Issue: Memory leak potential
    fun cleanup() {
        // Issue: No graceful shutdown of coroutines
        scope.cancel()
        
        // Issue: No proper data persistence before cleanup
        transactions.clear()
        dailyLimits.clear()
    }

    // Issue: No input validation
    // Issue: Direct transaction manipulation
    fun forceCompleteTransaction(transactionId: String, adminUserId: String) {
        val transaction = transactions[transactionId]
        
        // Issue: No authorization check for admin operations
        // Issue: No audit logging for admin overrides
        if (transaction != null) {
            transaction.status = "ADMIN_COMPLETED"
            transaction.metadata["adminOverride"] = adminUserId
            transaction.metadata["overrideTimestamp"] = LocalDateTime.now()
            
            // Issue: Basic logging for sensitive admin action
            println("Transaction force completed by admin: $adminUserId")
        }
    }
}

// Issue: No proper dependency injection
// Issue: Singleton pattern issues in concurrent environment
object TransactionServiceInstance {
    val instance: TransactionService by lazy { TransactionService() }
}