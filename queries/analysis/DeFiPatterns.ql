/**
 * @name DeFi pattern analysis
 * @description Analyzes DeFi patterns: math operations, fees, accounting, rounding.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/defi-patterns
 * @tags analysis
 *       defi
 *       math
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter

/**
 * Gets the contract name.
 */
string getContractName(Solidity::ContractDeclaration contract) {
  result = contract.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the function name.
 */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Detects division operations (precision loss risk).
 * Output: JSON with type, contract, function, file, line
 */
string formatDivision(Solidity::BinaryExpression expr) {
  expr.getOperator().(Solidity::AstNode).getValue() = "/" and
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract |
    expr.getParent+() = func and
    func.getParent+() = contract and
    result =
      "{\"type\":\"division\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\""
        + getFunctionName(func) + "\",\"file\":\"" + expr.getLocation().getFile().getName()
        + "\",\"line\":\"" + expr.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects multiplication operations.
 * Output: JSON with type, contract, function, file, line
 */
string formatMultiplication(Solidity::BinaryExpression expr) {
  expr.getOperator().(Solidity::AstNode).getValue() = "*" and
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract |
    expr.getParent+() = func and
    func.getParent+() = contract and
    result =
      "{\"type\":\"multiplication\",\"contract\":\"" + getContractName(contract)
        + "\",\"function\":\"" + getFunctionName(func) + "\",\"file\":\""
        + expr.getLocation().getFile().getName() + "\",\"line\":\""
        + expr.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects modulo operations (remainder calculations).
 * Output: JSON with type, contract, function, file, line
 */
string formatModulo(Solidity::BinaryExpression expr) {
  expr.getOperator().(Solidity::AstNode).getValue() = "%" and
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract |
    expr.getParent+() = func and
    func.getParent+() = contract and
    result =
      "{\"type\":\"modulo\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\""
        + getFunctionName(func) + "\",\"file\":\"" + expr.getLocation().getFile().getName()
        + "\",\"line\":\"" + expr.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects fee-related state variables.
 * Output: JSON with type, contract, name, type, file, line
 */
string formatFeeVariable(Solidity::StateVariableDeclaration var) {
  exists(Solidity::ContractDeclaration contract, string varName |
    var.getParent+() = contract and
    varName = var.getName().(Solidity::AstNode).getValue() and
    (
      varName.toLowerCase().matches("%fee%") or
      varName.toLowerCase().matches("%tax%") or
      varName.toLowerCase().matches("%rate%") or
      varName.toLowerCase().matches("%basis%") or
      varName.toLowerCase().matches("%percent%") or
      varName.toLowerCase().matches("%bps%")
    ) and
    result =
      "{\"type\":\"fee_var\",\"contract\":\"" + getContractName(contract) + "\",\"name\":\""
        + varName + "\",\"type\":\"" + var.getType().(Solidity::AstNode).toString()
        + "\",\"file\":\"" + var.getLocation().getFile().getName() + "\",\"line\":\""
        + var.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects balance/amount state variables (double accounting candidates).
 * Output: JSON with type, contract, name, type, file, line
 */
string formatBalanceVariable(Solidity::StateVariableDeclaration var) {
  exists(Solidity::ContractDeclaration contract, string varName |
    var.getParent+() = contract and
    varName = var.getName().(Solidity::AstNode).getValue() and
    (
      varName.toLowerCase().matches("%balance%") or
      varName.toLowerCase().matches("%amount%") or
      varName.toLowerCase().matches("%total%") or
      varName.toLowerCase().matches("%reserve%") or
      varName.toLowerCase().matches("%supply%") or
      varName.toLowerCase().matches("%liquidity%")
    ) and
    result =
      "{\"type\":\"balance_var\",\"contract\":\"" + getContractName(contract) + "\",\"name\":\""
        + varName + "\",\"type\":\"" + var.getType().(Solidity::AstNode).toString()
        + "\",\"file\":\"" + var.getLocation().getFile().getName() + "\",\"line\":\""
        + var.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects state variable assignments in functions.
 * Output: JSON with type, contract, function, variable, file, line
 */
string formatStateWrite(Solidity::AssignmentExpression assign) {
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract,
    Solidity::Identifier id, Solidity::StateVariableDeclaration sv
  |
    assign.getParent+() = func and
    func.getParent+() = contract and
    id.getParent+() = assign.getLeft() and
    sv.getParent+() = contract and
    sv.getName().(Solidity::AstNode).getValue() = id.getValue() and
    result =
      "{\"type\":\"state_write\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\""
        + getFunctionName(func) + "\",\"variable\":\"" + id.getValue() + "\",\"file\":\""
        + assign.getLocation().getFile().getName() + "\",\"line\":\""
        + assign.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects unchecked blocks (potential overflow in Solidity 0.8+).
 * Output: JSON with type, contract, function, file, line
 */
string formatUncheckedBlock(Solidity::Unchecked block) {
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract |
    block.getParent+() = func and
    func.getParent+() = contract and
    result =
      "{\"type\":\"unchecked\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\""
        + getFunctionName(func) + "\",\"file\":\"" + block.getLocation().getFile().getName()
        + "\",\"line\":\"" + block.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects magic numbers (literal values that may need constants).
 * Output: JSON with type, contract, function, value, file, line
 */
string formatMagicNumber(Solidity::NumberLiteral literal) {
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract, string value |
    literal.getParent+() = func and
    func.getParent+() = contract and
    value = literal.getValue() and
    // Filter out common non-magic numbers
    value != "0" and
    value != "1" and
    value != "2" and
    not value.matches("10%") and // powers of 10
    not value.matches("1e%") and
    // Check if it looks like a significant number
    (
      value.toInt() > 100 or
      value.matches("%000%")
    ) and
    result =
      "{\"type\":\"magic_number\",\"contract\":\"" + getContractName(contract)
        + "\",\"function\":\"" + getFunctionName(func) + "\",\"value\":\"" + value
        + "\",\"file\":\"" + literal.getLocation().getFile().getName() + "\",\"line\":\""
        + literal.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects potential rounding direction issues (division before multiplication).
 * This is a heuristic - division followed by multiplication in same expression.
 * Output: JSON with type, contract, function, file, line
 */
string formatRoundingRisk(Solidity::BinaryExpression multExpr) {
  multExpr.getOperator().(Solidity::AstNode).getValue() = "*" and
  exists(
    Solidity::BinaryExpression divExpr, Solidity::FunctionDefinition func,
    Solidity::ContractDeclaration contract
  |
    divExpr.getOperator().(Solidity::AstNode).getValue() = "/" and
    divExpr.getParent+() = multExpr and
    multExpr.getParent+() = func and
    func.getParent+() = contract and
    result =
      "{\"type\":\"rounding_risk\",\"contract\":\"" + getContractName(contract)
        + "\",\"function\":\"" + getFunctionName(func) + "\",\"file\":\""
        + multExpr.getLocation().getFile().getName() + "\",\"line\":\""
        + multExpr.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects price/oracle related variables.
 * Output: JSON with type, contract, name, file, line
 */
string formatPriceVariable(Solidity::StateVariableDeclaration var) {
  exists(Solidity::ContractDeclaration contract, string varName |
    var.getParent+() = contract and
    varName = var.getName().(Solidity::AstNode).getValue() and
    (
      varName.toLowerCase().matches("%price%") or
      varName.toLowerCase().matches("%oracle%") or
      varName.toLowerCase().matches("%rate%") or
      varName.toLowerCase().matches("%exchange%")
    ) and
    result =
      "{\"type\":\"price_var\",\"contract\":\"" + getContractName(contract) + "\",\"name\":\""
        + varName + "\",\"file\":\"" + var.getLocation().getFile().getName() + "\",\"line\":\""
        + var.getLocation().getStartLine().toString() + "\"}"
  )
}

// Main query
from string info
where
  info = formatDivision(_)
  or
  info = formatMultiplication(_)
  or
  info = formatModulo(_)
  or
  info = formatFeeVariable(_)
  or
  info = formatBalanceVariable(_)
  or
  info = formatStateWrite(_)
  or
  info = formatUncheckedBlock(_)
  or
  info = formatMagicNumber(_)
  or
  info = formatRoundingRisk(_)
  or
  info = formatPriceVariable(_)
select info, info
