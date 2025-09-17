// LendingService.kt - Contains issues that Greptile would catch for Kotlin backend
package com.circular.lending

import java.math.BigDecimal
import java.time.LocalDateTime
import kotlinx.coroutines.delay

// Issue: Missing data validation annotations
data class LoanApplication(
    val userId: String,
    val amount: BigDecimal, // Good: Using BigDecimal for money
    val creditScore: Int,
    val income: BigDecimal?,  // Issue: Should be non-null for lending decisions
    val purpose: String?
)

// Issue: Missing proper error handling sealed classes
data class LoanDecision(
    val approved: Boolean,
    val reason: String?,
    val interestRate: Double? // Issue: Should use BigDecimal for rates
)

class LendingService(
    private val creditService: CreditService,
    private val riskEngine: RiskEngine,
    private val auditLogger: AuditLogger
) {
    
    // Issue: Missing suspend function for async operations
    // Issue: No proper error handling
    // Issue: Missing audit logging
    fun processLoanApplication(application: LoanApplication): LoanDecision {
        // Issue: No input validation
        // Issue: No null check for income
        if (application.amount <= BigDecimal.ZERO) {
            return LoanDecision(false, "Invalid loan amount", null)
        }

        try {
            // Issue: Blocking call in what should be async function
            val creditReport = creditService.getCreditReport(application.userId)
            
            // Issue: Magic numbers - should be configuration
            if (application.creditScore < 650) {
                // Issue: Missing compliance logging for loan rejection
                return LoanDecision(false, "Credit score too low", null)
            }

            // Issue: Potential division by zero
            // Issue: Using raw division for financial calculations
            val debtToIncomeRatio = application.amount.toDouble() / application.income!!.toDouble()
            
            // Issue: No proper logging with transaction ID
            println("Processing loan for user: ${application.userId}") // Basic logging

            // Issue: No timeout handling for external service
            val riskAssessment = riskEngine.assessRisk(application)
            
            val approved = riskAssessment.score > 0.7 // Issue: Magic number
            val rate = calculateInterestRate(application.creditScore) // Issue: Could return null
            
            // Issue: Missing SOX compliance audit trail
            return LoanDecision(approved, "Risk assessment complete", rate)
            
        } catch (e: Exception) {
            // Issue: Logging sensitive information
            // Issue: Generic exception handling
            println("Loan processing failed for ${application.userId}: ${e.message}")
            throw e // Issue: Propagating technical errors to API layer
        }
    }

    // Issue: Returns nullable Double instead of Result type
    private fun calculateInterestRate(creditScore: Int): Double? {
        // Issue: No input validation
        // Issue: Hard-coded rate calculations
        return when {
            creditScore >= 800 -> 3.5
            creditScore >= 750 -> 4.0
            creditScore >= 700 -> 4.5
            creditScore >= 650 -> 5.5
            else -> null // Issue: Should use sealed class for results
        }
    }

    // Issue: Missing proper coroutine handling
    // Issue: No circuit breaker for external calls
    suspend fun checkExternalCreditBureau(userId: String): String {
        // Issue: No timeout specified
        delay(2000) // Simulating slow external service
        
        // Issue: No error handling for external service failures
        // Issue: Hardcoded URL
        val response = creditService.queryBureau("https://api.creditbureau.com/check/$userId")
        
        // Issue: No null check
        return response.status
    }

    // Issue: No proper transaction management
    // Issue: Missing audit logging for account modifications
    fun approveLoan(loanId: String, userId: String, amount: BigDecimal) {
        // Issue: No authorization checks
        // Issue: No input validation
        
        try {
            // Issue: Multiple database operations not in transaction
            val account = accountRepository.findByUserId(userId)
            accountRepository.updateBalance(account.id, account.balance + amount)
            loanRepository.updateStatus(loanId, "APPROVED")
            
            // Issue: Insufficient audit logging for financial operation
            // Should include: timestamp, loan officer ID, amount, terms, etc.
            auditLogger.log("Loan approved: $loanId")
            
        } catch (e: Exception) {
            // Issue: No proper error recovery
            // Issue: No rollback mechanism
            throw RuntimeException("Failed to approve loan", e)
        }
    }
}

// Issue: Missing proper dependency injection
// Issue: No configuration management
object LendingConfig {
    const val MIN_CREDIT_SCORE = 650  // Should be configurable
    const val MAX_DEBT_TO_INCOME = 0.43 // Magic number
    
    // Issue: Sensitive configuration in code
    const val EXTERNAL_API_KEY = "sk_test_123456" // Should be in secure config
}