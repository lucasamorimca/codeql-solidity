/**
 * @name Storage layout analysis
 * @description Analyzes storage slots, gaps, and variable layout for upgradeable contracts.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/storage-layout
 * @tags analysis
 *       storage
 *       upgradeable
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter

/**
 * Gets the contract name from a contract declaration.
 */
string getContractName(Solidity::ContractDeclaration contract) {
  result = contract.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets visibility of a state variable.
 */
string getStateVarVisibility(Solidity::StateVariableDeclaration var) {
  exists(Solidity::AstNode vis |
    vis.getParent() = var and
    vis.toString() = "Visibility" and
    result = vis.getAChild().getValue()
  )
  or
  not exists(Solidity::AstNode vis |
    vis.getParent() = var and
    vis.toString() = "Visibility"
  ) and
  result = "internal"
}

/**
 * Holds if a state variable is constant.
 */
predicate isConstant(Solidity::StateVariableDeclaration var) {
  exists(Solidity::AstNode c |
    c.getParent() = var and
    c.getValue() = "constant"
  )
}

/**
 * Holds if a state variable is immutable.
 */
predicate isImmutable(Solidity::StateVariableDeclaration var) {
  exists(Solidity::AstNode i |
    i.getParent() = var and
    i.getValue() = "immutable"
  )
}

/**
 * Gets the type string of a state variable.
 */
string getTypeString(Solidity::StateVariableDeclaration var) {
  exists(Solidity::AstNode typeNode |
    typeNode = var.getType() and
    result = typeNode.toString()
  )
  or
  not exists(var.getType()) and result = "unknown"
}

/**
 * Calculates the size in bytes of a Solidity type.
 */
bindingset[typeStr]
int getTypeSize(string typeStr) {
  // uint/int types
  typeStr.regexpMatch(".*uint(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?.*") and
  (
    typeStr.regexpMatch(".*uint8.*") and result = 1
    or
    typeStr.regexpMatch(".*uint16.*") and result = 2
    or
    typeStr.regexpMatch(".*uint24.*") and result = 3
    or
    typeStr.regexpMatch(".*uint32.*") and result = 4
    or
    typeStr.regexpMatch(".*uint64.*") and result = 8
    or
    typeStr.regexpMatch(".*uint128.*") and result = 16
    or
    typeStr.regexpMatch(".*uint256.*") and result = 32
    or
    typeStr.regexpMatch(".*uint[^0-9].*") and result = 32
    or
    typeStr = "uint" and result = 32
  )
  or
  typeStr.regexpMatch(".*int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?.*") and
  not typeStr.regexpMatch(".*uint.*") and
  (
    typeStr.regexpMatch(".*int8.*") and result = 1
    or
    typeStr.regexpMatch(".*int16.*") and result = 2
    or
    typeStr.regexpMatch(".*int32.*") and result = 4
    or
    typeStr.regexpMatch(".*int64.*") and result = 8
    or
    typeStr.regexpMatch(".*int128.*") and result = 16
    or
    typeStr.regexpMatch(".*int256.*") and result = 32
    or
    typeStr.regexpMatch(".*int[^0-9].*") and result = 32
  )
  or
  // address
  typeStr.toLowerCase().matches("%address%") and result = 20
  or
  // bool
  typeStr.toLowerCase() = "bool" and result = 1
  or
  // bytes1-32
  typeStr.regexpMatch(".*bytes[0-9]+.*") and
  (
    typeStr.regexpMatch(".*bytes1[^0-9].*") and result = 1
    or
    typeStr.regexpMatch(".*bytes4.*") and result = 4
    or
    typeStr.regexpMatch(".*bytes8.*") and result = 8
    or
    typeStr.regexpMatch(".*bytes16.*") and result = 16
    or
    typeStr.regexpMatch(".*bytes20.*") and result = 20
    or
    typeStr.regexpMatch(".*bytes32.*") and result = 32
  )
  or
  // Dynamic types take a full slot (pointer)
  (
    typeStr.toLowerCase().matches("%mapping%") or
    typeStr.toLowerCase().matches("%string%") or
    typeStr.toLowerCase().matches("%bytes%") and not typeStr.regexpMatch(".*bytes[0-9]+.*") or
    typeStr.matches("%[]%")
  ) and
  result = 32
  or
  // Structs and other types default to full slot
  not typeStr.regexpMatch(".*uint.*") and
  not typeStr.regexpMatch(".*int.*") and
  not typeStr.toLowerCase().matches("%address%") and
  not typeStr.toLowerCase() = "bool" and
  not typeStr.regexpMatch(".*bytes.*") and
  not typeStr.toLowerCase().matches("%mapping%") and
  not typeStr.toLowerCase().matches("%string%") and
  not typeStr.matches("%[]%") and
  result = 32
}

/**
 * State variable storage information.
 * Output: JSON with type, contract, name, type, visibility, is_constant, is_immutable, size, file, line
 */
string formatStateVariable(Solidity::StateVariableDeclaration var) {
  exists(
    Solidity::ContractDeclaration contract, string varName, string varType, string visibility,
    string isConst, string isImm, int size
  |
    var.getParent+() = contract and
    varName = var.getName().(Solidity::AstNode).getValue() and
    varType = getTypeString(var) and
    visibility = getStateVarVisibility(var) and
    (if isConstant(var) then isConst = "true" else isConst = "false") and
    (if isImmutable(var) then isImm = "true" else isImm = "false") and
    size = getTypeSize(varType) and
    result =
      "{\"type\":\"storage\",\"contract\":\"" + getContractName(contract) + "\",\"name\":\"" + varName
        + "\",\"type\":\"" + varType + "\",\"visibility\":\"" + visibility + "\",\"is_constant\":\""
        + isConst + "\",\"is_immutable\":\"" + isImm + "\",\"size\":\"" + size.toString()
        + "\",\"file\":\"" + var.getLocation().getFile().getName() + "\",\"line\":\""
        + var.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects storage gaps for upgradeability.
 * Output: JSON with type, contract, name, type, file, line
 */
string formatStorageGap(Solidity::StateVariableDeclaration var) {
  exists(Solidity::ContractDeclaration contract, string varName, string varType |
    var.getParent+() = contract and
    varName = var.getName().(Solidity::AstNode).getValue() and
    varType = getTypeString(var) and
    (
      varName.toLowerCase().matches("%__gap%") or
      varName.toLowerCase().matches("%_gap%") or
      varName.toLowerCase().matches("%gap%")
    ) and
    varType.matches("%[%]%") and
    result =
      "{\"type\":\"gap\",\"contract\":\"" + getContractName(contract) + "\",\"name\":\"" + varName
        + "\",\"type\":\"" + varType + "\",\"file\":\""
        + var.getLocation().getFile().getName() + "\",\"line\":\""
        + var.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Contract storage summary.
 * Output: JSON with type, contract, total_vars, constant_count, immutable_count, file, line
 */
string formatContractStorageSummary(Solidity::ContractDeclaration contract) {
  exists(int totalVars, int constCount, int immCount |
    totalVars =
      count(Solidity::StateVariableDeclaration v |
        v.getParent+() = contract and not isConstant(v) and not isImmutable(v)
      ) and
    constCount = count(Solidity::StateVariableDeclaration v | v.getParent+() = contract and isConstant(v)) and
    immCount = count(Solidity::StateVariableDeclaration v | v.getParent+() = contract and isImmutable(v)) and
    result =
      "{\"type\":\"summary\",\"contract\":\"" + getContractName(contract) + "\",\"total_vars\":\""
        + totalVars.toString() + "\",\"constant_count\":\"" + constCount.toString()
        + "\",\"immutable_count\":\"" + immCount.toString() + "\",\"file\":\""
        + contract.getLocation().getFile().getName() + "\",\"line\":\""
        + contract.getLocation().getStartLine().toString() + "\"}"
  )
}

// Main query
from string info
where
  info = formatStateVariable(_)
  or
  info = formatStorageGap(_)
  or
  info = formatContractStorageSummary(_)
select info, info
