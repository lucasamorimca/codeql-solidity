/**
 * Contract-related nodes in Solidity AST.
 *
 * This module provides classes for contracts, interfaces, libraries,
 * and their members.
 */

private import codeql.solidity.ast.internal.TreeSitter
private import codeql.solidity.ast.Function

/**
 * A contract, interface, or library definition.
 */
class ContractLike extends Solidity::AstNode {
  ContractLike() {
    this instanceof Solidity::ContractDeclaration or
    this instanceof Solidity::InterfaceDeclaration or
    this instanceof Solidity::LibraryDeclaration
  }

  /** Gets the name of this contract/interface/library as a string. */
  string getContractName() { none() } // Overridden in subclasses

  /** Gets the name node of this contract/interface/library. */
  Solidity::AstNode getNameNode() { none() } // Overridden in subclasses

  /** Gets the body of this contract/interface/library. */
  Solidity::AstNode getBodyNode() { none() } // Overridden in subclasses

  /** Gets a member of this contract/interface/library. */
  Solidity::AstNode getAMember() { result = this.getBodyNode().getAChild() }

  /** Gets a function defined in this contract/interface/library. */
  FunctionDef getAFunction() { result = this.getAMember() }

  /** Gets a function by name. */
  FunctionDef getFunction(string name) {
    result = this.getAFunction() and result.getFunctionName() = name
  }

  /** Gets the constructor, if any. */
  ConstructorDef getConstructor() { result = this.getAMember() }

  /** Gets a state variable. */
  StateVariable getAStateVariable() { result = this.getAMember() }

  /** Gets a state variable by name. */
  StateVariable getStateVariable(string name) {
    result = this.getAStateVariable() and result.getVariableName() = name
  }
}

/**
 * A contract definition.
 */
class Contract extends Solidity::ContractDeclaration, ContractLike {
  override string getContractName() {
    exists(Solidity::AstNode name | name = Solidity::ContractDeclaration.super.getName() |
      solidity_tokeninfo(name, _, result)
    )
  }

  override Solidity::AstNode getNameNode() { result = Solidity::ContractDeclaration.super.getName() }

  override Solidity::AstNode getBodyNode() { result = Solidity::ContractDeclaration.super.getBody() }

  /** Gets a base contract (inheritance). */
  Solidity::InheritanceSpecifier getABaseContract() {
    result = this.getAChild()
  }

  /** Holds if this contract is abstract. */
  predicate isAbstract() {
    exists(Solidity::AstNode mod | mod = this.getAChild() |
      solidity_tokeninfo(mod, _, "abstract")
    )
  }
}

/**
 * An interface definition.
 */
class Interface extends Solidity::InterfaceDeclaration, ContractLike {
  override string getContractName() {
    exists(Solidity::AstNode name | name = Solidity::InterfaceDeclaration.super.getName() |
      solidity_tokeninfo(name, _, result)
    )
  }

  override Solidity::AstNode getNameNode() { result = Solidity::InterfaceDeclaration.super.getName() }

  override Solidity::AstNode getBodyNode() { result = Solidity::InterfaceDeclaration.super.getBody() }

  /** Gets a base interface (inheritance). */
  Solidity::InheritanceSpecifier getABaseInterface() {
    result = this.getAChild()
  }
}

/**
 * A library definition.
 */
class Library extends Solidity::LibraryDeclaration, ContractLike {
  override string getContractName() {
    exists(Solidity::AstNode name | name = Solidity::LibraryDeclaration.super.getName() |
      solidity_tokeninfo(name, _, result)
    )
  }

  override Solidity::AstNode getNameNode() { result = Solidity::LibraryDeclaration.super.getName() }

  override Solidity::AstNode getBodyNode() { result = Solidity::LibraryDeclaration.super.getBody() }
}

/**
 * A state variable declaration.
 */
class StateVariable extends Solidity::StateVariableDeclaration {
  /** Gets the name of this state variable as a string. */
  string getVariableName() {
    exists(Solidity::AstNode name | name = super.getName() |
      solidity_tokeninfo(name, _, result)
    )
  }

  /** Gets the type of this state variable. */
  Solidity::AstNode getTypeNode() { result = super.getType() }

  /** Gets the visibility (public, internal, private). */
  string getVisibility() {
    exists(Solidity::AstNode vis | vis = super.getAVisibility() |
      solidity_tokeninfo(vis, _, result)
    )
    or
    not exists(super.getAVisibility()) and result = "internal"
  }

  /** Gets the initial value expression, if any. */
  Solidity::AstNode getInitializer() { result = super.getFieldValue() }

  /** Holds if this is a public state variable. */
  predicate isPublic() { this.getVisibility() = "public" }

  /** Holds if this variable is immutable. */
  predicate isImmutable() {
    exists(Solidity::AstNode mod | mod = this.getAChild() |
      solidity_tokeninfo(mod, _, "immutable")
    )
  }

  /** Holds if this variable is constant. */
  predicate isConstant() {
    exists(Solidity::AstNode mod | mod = this.getAChild() |
      solidity_tokeninfo(mod, _, "constant")
    )
  }
}

/**
 * A struct definition.
 */
class StructDef extends Solidity::StructDeclaration {
  /** Gets the name of this struct as a string. */
  string getStructName() {
    exists(Solidity::AstNode name | name = super.getName() |
      solidity_tokeninfo(name, _, result)
    )
  }

  /** Gets a member of this struct. */
  Solidity::AstNode getAMember() { result = super.getBody().getAChild() }
}

/**
 * An enum definition.
 */
class EnumDef extends Solidity::EnumDeclaration {
  /** Gets the name of this enum as a string. */
  string getEnumName() {
    exists(Solidity::AstNode name | name = super.getName() |
      solidity_tokeninfo(name, _, result)
    )
  }

  /** Gets a value of this enum. */
  Solidity::AstNode getAValue() { result = super.getBody().getAChild() }
}

/**
 * An event definition.
 */
class EventDef extends Solidity::EventDefinition {
  /** Gets the name of this event as a string. */
  string getEventName() {
    exists(Solidity::AstNode name | name = super.getName() |
      solidity_tokeninfo(name, _, result)
    )
  }

  /** Gets a parameter of this event. */
  Solidity::AstNode getAParameter() { result = this.getAChild() }
}

/**
 * An error definition.
 */
class ErrorDef extends Solidity::ErrorDeclaration {
  /** Gets the name of this error as a string. */
  string getErrorName() {
    exists(Solidity::AstNode name | name = super.getName() |
      solidity_tokeninfo(name, _, result)
    )
  }

  /** Gets a parameter of this error. */
  Solidity::AstNode getAParameter() { result = this.getAChild() }
}

/**
 * A using directive (e.g., `using SafeMath for uint256`).
 */
class UsingDirective_ extends Solidity::UsingDirective {
  /** Gets the library being used. */
  Solidity::AstNode getLibrary() { result = super.getSource() }

  /** Gets the type this is applied to, if any. */
  Solidity::AstNode getTargetType() { result = this.getAChild() }
}

/**
 * An inheritance specifier.
 */
class InheritanceSpecifier_ extends Solidity::InheritanceSpecifier {
  /** Gets the base contract/interface name. */
  Solidity::AstNode getBaseName() { result = super.getAncestor() }

  /** Gets a constructor argument. */
  Solidity::AstNode getAnArgument() { result = super.getAAncestorArguments().getAChild() }
}
