/**
 * CodeQL library for Solidity AST (tree-sitter wrapper classes)
 * Automatically generated from tree-sitter grammar; do not edit
 */

// Basic infrastructure types

/** A source file */
class File extends @file {
    /** Gets the name/path of this file */
    string getName() { files(this, result) }

    /** Gets a string representation */
    string toString() { result = this.getName() }
}

/** A source location */
class Location extends @location_default {
    /** Gets the file containing this location */
    File getFile() { locations_default(this, result, _, _, _, _) }

    /** Gets the start line (1-based) */
    int getStartLine() { locations_default(this, _, result, _, _, _) }

    /** Gets the start column (1-based) */
    int getStartColumn() { locations_default(this, _, _, result, _, _) }

    /** Gets the end line (1-based) */
    int getEndLine() { locations_default(this, _, _, _, result, _) }

    /** Gets the end column (1-based) */
    int getEndColumn() { locations_default(this, _, _, _, _, result) }

    /** Gets a string representation */
    string toString() {
        result = this.getFile().getName() + ":" + this.getStartLine().toString()
    }
}

/** Module containing tree-sitter wrapper classes */
module Solidity {

    /** Base class for all Solidity AST nodes */
    class AstNode extends @solidity_ast_node {
        /** Gets a string representation of this node */
        string toString() { result = this.getAPrimaryQlClass() }

        /** Gets the primary QL class name for this node */
        string getAPrimaryQlClass() { result = "AstNode" }

        /** Gets the location of this node */
        Location getLocation() {
            solidity_ast_node_location(this, result)
        }

        /** Gets the token text value of this node (for leaf nodes like identifiers) */
        string getValue() {
            solidity_tokeninfo(this, _, result)
        }

        /** Gets the parent of this node, if any */
        AstNode getParent() {
            solidity_ast_node_parent(this, result, _)
        }

        /** Gets the index of this node in its parent's children */
        int getParentIndex() {
            solidity_ast_node_parent(this, _, result)
        }

        /** Gets a child of this node */
        AstNode getAChild() {
            solidity_ast_node_parent(result, this, _)
        }

        /** Gets the i-th child of this node */
        AstNode getChild(int i) {
            solidity_ast_node_parent(result, this, i)
        }

        /** Gets the number of children */
        int getNumChildren() {
            result = count(this.getAChild())
        }

        /** Gets any descendant of this node (including itself) */
        AstNode getADescendant() {
            result = this
            or
            result = this.getAChild().getADescendant()
        }

        /** Gets any field or child of this node */
        AstNode getAFieldOrChild() {
            result = this.getAChild()
        }

        /** Gets the file containing this node */
        File getFile() {
            result = this.getLocation().getFile()
        }
    }

    /** A `any_pragma_token` node in the AST */
    class AnyPragmaToken extends @solidity_any_pragma_token, AstNode {
        override string getAPrimaryQlClass() { result = "AnyPragmaToken" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_any_pragma_token_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `any_source_type` node in the AST */
    class AnySourceType extends @solidity_any_source_type, AstNode {
        override string getAPrimaryQlClass() { result = "AnySourceType" }

    }

    /** A `array_access` node in the AST */
    class ArrayAccess extends @solidity_array_access, AstNode {
        override string getAPrimaryQlClass() { result = "ArrayAccess" }

        /** Gets the index */
        AstNode getIndex() { solidity_array_access_index(this, 0, result) }

        /** Gets the base */
        AstNode getBase() { solidity_array_access_base(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getIndex()
            or result = this.getBase()
        }

    }

    /** A `assembly_flags` node in the AST */
    class AssemblyFlags extends @solidity_assembly_flags, AstNode {
        override string getAPrimaryQlClass() { result = "AssemblyFlags" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_assembly_flags_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `assembly_statement` node in the AST */
    class AssemblyStatement extends @solidity_assembly_statement, AstNode {
        override string getAPrimaryQlClass() { result = "AssemblyStatement" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_assembly_statement_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `assignment_expression` node in the AST */
    class AssignmentExpression extends @solidity_assignment_expression, AstNode {
        override string getAPrimaryQlClass() { result = "AssignmentExpression" }

        /** Gets the right */
        AstNode getRight() { solidity_assignment_expression_right(this, 0, result) }

        /** Gets the left */
        AstNode getLeft() { solidity_assignment_expression_left(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getRight()
            or result = this.getLeft()
        }

    }

    /** A `augmented_assignment_expression` node in the AST */
    class AugmentedAssignmentExpression extends @solidity_augmented_assignment_expression, AstNode {
        override string getAPrimaryQlClass() { result = "AugmentedAssignmentExpression" }

        /** Gets the left */
        AstNode getLeft() { solidity_augmented_assignment_expression_left(this, 0, result) }

        /** Gets the right */
        AstNode getRight() { solidity_augmented_assignment_expression_right(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getLeft()
            or result = this.getRight()
        }

    }

    /** A `binary_expression` node in the AST */
    class BinaryExpression extends @solidity_binary_expression, AstNode {
        override string getAPrimaryQlClass() { result = "BinaryExpression" }

        /** Gets the right */
        AstNode getRight() { solidity_binary_expression_right(this, 0, result) }

        /** Gets the left */
        AstNode getLeft() { solidity_binary_expression_left(this, 0, result) }

        /** Gets the operator */
        AstNode getOperator() { solidity_binary_expression_operator(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getRight()
            or result = this.getLeft()
            or result = this.getOperator()
        }

    }

    /** A `block_statement` node in the AST */
    class BlockStatement extends @solidity_block_statement, AstNode {
        override string getAPrimaryQlClass() { result = "BlockStatement" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_block_statement_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `boolean_literal` node in the AST */
    class BooleanLiteral extends @solidity_boolean_literal, AstNode {
        override string getAPrimaryQlClass() { result = "BooleanLiteral" }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `break_statement` node in the AST */
    class BreakStatement extends @solidity_break_statement, AstNode {
        override string getAPrimaryQlClass() { result = "BreakStatement" }

    }

    /** A `call_argument` node in the AST */
    class CallArgument extends @solidity_call_argument, AstNode {
        override string getAPrimaryQlClass() { result = "CallArgument" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_call_argument_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `call_expression` node in the AST */
    class CallExpression extends @solidity_call_expression, AstNode {
        override string getAPrimaryQlClass() { result = "CallExpression" }

        /** Gets the function */
        AstNode getFunction() { solidity_call_expression_function(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_call_expression_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getFunction()
        }

    }

    /** A `call_struct_argument` node in the AST */
    class CallStructArgument extends @solidity_call_struct_argument, AstNode {
        override string getAPrimaryQlClass() { result = "CallStructArgument" }

        /** Gets the name */
        AstNode getName() { solidity_call_struct_argument_name(this, 0, result) }

        /** Gets the field_value */
        AstNode getFieldValue() { solidity_call_struct_argument_value(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getName()
            or result = this.getFieldValue()
        }

    }

    /** A `catch_clause` node in the AST */
    class CatchClause extends @solidity_catch_clause, AstNode {
        override string getAPrimaryQlClass() { result = "CatchClause" }

        /** Gets the body */
        AstNode getBody() { solidity_catch_clause_body(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_catch_clause_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getBody()
        }

    }

    /** A `constant_variable_declaration` node in the AST */
    class ConstantVariableDeclaration extends @solidity_constant_variable_declaration, AstNode {
        override string getAPrimaryQlClass() { result = "ConstantVariableDeclaration" }

        /** Gets the type */
        AstNode getType() { solidity_constant_variable_declaration_type(this, 0, result) }

        /** Gets the field_value */
        AstNode getFieldValue() { solidity_constant_variable_declaration_value(this, 0, result) }

        /** Gets the name */
        AstNode getName() { solidity_constant_variable_declaration_name(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getType()
            or result = this.getFieldValue()
            or result = this.getName()
        }

    }

    /** A `constructor_definition` node in the AST */
    class ConstructorDefinition extends @solidity_constructor_definition, AstNode {
        override string getAPrimaryQlClass() { result = "ConstructorDefinition" }

        /** Gets the body */
        AstNode getBody() { solidity_constructor_definition_body(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_constructor_definition_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getBody()
        }

    }

    /** A `continue_statement` node in the AST */
    class ContinueStatement extends @solidity_continue_statement, AstNode {
        override string getAPrimaryQlClass() { result = "ContinueStatement" }

    }

    /** A `contract_body` node in the AST */
    class ContractBody extends @solidity_contract_body, AstNode {
        override string getAPrimaryQlClass() { result = "ContractBody" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_contract_body_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `contract_declaration` node in the AST */
    class ContractDeclaration extends @solidity_contract_declaration, AstNode {
        override string getAPrimaryQlClass() { result = "ContractDeclaration" }

        /** Gets the name */
        AstNode getName() { solidity_contract_declaration_name(this, 0, result) }

        /** Gets the body */
        AstNode getBody() { solidity_contract_declaration_body(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_contract_declaration_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getName()
            or result = this.getBody()
        }

    }

    /** A `do_while_statement` node in the AST */
    class DoWhileStatement extends @solidity_do_while_statement, AstNode {
        override string getAPrimaryQlClass() { result = "DoWhileStatement" }

        /** Gets the condition */
        AstNode getCondition() { solidity_do_while_statement_condition(this, 0, result) }

        /** Gets the body */
        AstNode getBody() { solidity_do_while_statement_body(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getCondition()
            or result = this.getBody()
        }

    }

    /** A `emit_statement` node in the AST */
    class EmitStatement extends @solidity_emit_statement, AstNode {
        override string getAPrimaryQlClass() { result = "EmitStatement" }

        /** Gets the name */
        AstNode getName() { solidity_emit_statement_name(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_emit_statement_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getName()
        }

    }

    /** A `enum_body` node in the AST */
    class EnumBody extends @solidity_enum_body, AstNode {
        override string getAPrimaryQlClass() { result = "EnumBody" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_enum_body_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `enum_declaration` node in the AST */
    class EnumDeclaration extends @solidity_enum_declaration, AstNode {
        override string getAPrimaryQlClass() { result = "EnumDeclaration" }

        /** Gets the body */
        AstNode getBody() { solidity_enum_declaration_body(this, 0, result) }

        /** Gets the name */
        AstNode getName() { solidity_enum_declaration_name(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getBody()
            or result = this.getName()
        }

    }

    /** A `error_declaration` node in the AST */
    class ErrorDeclaration extends @solidity_error_declaration, AstNode {
        override string getAPrimaryQlClass() { result = "ErrorDeclaration" }

        /** Gets the name */
        AstNode getName() { solidity_error_declaration_name(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_error_declaration_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getName()
        }

    }

    /** A `error_parameter` node in the AST */
    class ErrorParameter extends @solidity_error_parameter, AstNode {
        override string getAPrimaryQlClass() { result = "ErrorParameter" }

        /** Gets the name */
        AstNode getName() { solidity_error_parameter_name(this, 0, result) }

        /** Gets the type */
        AstNode getType() { solidity_error_parameter_type(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getName()
            or result = this.getType()
        }

    }

    /** A `event_definition` node in the AST */
    class EventDefinition extends @solidity_event_definition, AstNode {
        override string getAPrimaryQlClass() { result = "EventDefinition" }

        /** Gets the name */
        AstNode getName() { solidity_event_definition_name(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_event_definition_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getName()
        }

    }

    /** A `event_parameter` node in the AST */
    class EventParameter extends @solidity_event_parameter, AstNode {
        override string getAPrimaryQlClass() { result = "EventParameter" }

        /** Gets the type */
        AstNode getType() { solidity_event_parameter_type(this, 0, result) }

        /** Gets the name */
        AstNode getName() { solidity_event_parameter_name(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getType()
            or result = this.getName()
        }

    }

    /** A `expression` node in the AST */
    class Expression extends @solidity_expression, AstNode {
        override string getAPrimaryQlClass() { result = "Expression" }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `expression_statement` node in the AST */
    class ExpressionStatement extends @solidity_expression_statement, AstNode {
        override string getAPrimaryQlClass() { result = "ExpressionStatement" }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `fallback_receive_definition` node in the AST */
    class FallbackReceiveDefinition extends @solidity_fallback_receive_definition, AstNode {
        override string getAPrimaryQlClass() { result = "FallbackReceiveDefinition" }

        /** Gets the body */
        AstNode getBody() { solidity_fallback_receive_definition_body(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_fallback_receive_definition_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getBody()
        }

    }

    /** A `false` node in the AST */
    class False extends @solidity_false, AstNode {
        override string getAPrimaryQlClass() { result = "False" }

    }

    /** A `for_statement` node in the AST */
    class ForStatement extends @solidity_for_statement, AstNode {
        override string getAPrimaryQlClass() { result = "ForStatement" }

        /** Gets the initial */
        AstNode getInitial() { solidity_for_statement_initial(this, 0, result) }

        /** Gets the condition */
        AstNode getCondition() { solidity_for_statement_condition(this, 0, result) }

        /** Gets the update */
        AstNode getUpdate() { solidity_for_statement_update(this, 0, result) }

        /** Gets the body */
        AstNode getBody() { solidity_for_statement_body(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getInitial()
            or result = this.getCondition()
            or result = this.getUpdate()
            or result = this.getBody()
        }

    }

    /** A `function_body` node in the AST */
    class FunctionBody extends @solidity_function_body, AstNode {
        override string getAPrimaryQlClass() { result = "FunctionBody" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_function_body_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `function_definition` node in the AST */
    class FunctionDefinition extends @solidity_function_definition, AstNode {
        override string getAPrimaryQlClass() { result = "FunctionDefinition" }

        /** Gets the return_type */
        AstNode getReturnType() { solidity_function_definition_return_type(this, 0, result) }

        /** Gets the name */
        AstNode getName() { solidity_function_definition_name(this, 0, result) }

        /** Gets the body */
        AstNode getBody() { solidity_function_definition_body(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_function_definition_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getReturnType()
            or result = this.getName()
            or result = this.getBody()
        }

    }

    /** A `hex_string_literal` node in the AST */
    class HexStringLiteral extends @solidity_hex_string_literal, AstNode {
        override string getAPrimaryQlClass() { result = "HexStringLiteral" }

    }

    /** A `if_statement` node in the AST */
    class IfStatement extends @solidity_if_statement, AstNode {
        override string getAPrimaryQlClass() { result = "IfStatement" }

        /** Gets the condition */
        AstNode getCondition() { solidity_if_statement_condition(this, 0, result) }

        /** Gets the body at index `i` */
        AstNode getBody(int i) { solidity_if_statement_body(this, i, result) }

        /** Gets any body */
        AstNode getABody() { solidity_if_statement_body(this, _, result) }

        /** Gets the number of bodys */
        int getNumBodys() { result = count(this.getABody()) }

        /** Gets the else */
        AstNode getElse() { solidity_if_statement_else(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getCondition()
            or result = this.getABody()
            or result = this.getElse()
        }

    }

    /** A `import_directive` node in the AST */
    class ImportDirective extends @solidity_import_directive, AstNode {
        override string getAPrimaryQlClass() { result = "ImportDirective" }

        /** Gets the source */
        AstNode getSource() { solidity_import_directive_source(this, 0, result) }

        /** Gets the import_name at index `i` */
        AstNode getImportName(int i) { solidity_import_directive_import_name(this, i, result) }

        /** Gets any import_name */
        AstNode getAImportName() { solidity_import_directive_import_name(this, _, result) }

        /** Gets the number of import_names */
        int getNumImportNames() { result = count(this.getAImportName()) }

        /** Gets the alias at index `i` */
        AstNode getAlias(int i) { solidity_import_directive_alias(this, i, result) }

        /** Gets any alias */
        AstNode getAAlias() { solidity_import_directive_alias(this, _, result) }

        /** Gets the number of aliass */
        int getNumAliass() { result = count(this.getAAlias()) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getSource()
            or result = this.getAImportName()
            or result = this.getAAlias()
        }

    }

    /** A `inheritance_specifier` node in the AST */
    class InheritanceSpecifier extends @solidity_inheritance_specifier, AstNode {
        override string getAPrimaryQlClass() { result = "InheritanceSpecifier" }

        /** Gets the ancestor_arguments at index `i` */
        AstNode getAncestorArguments(int i) { solidity_inheritance_specifier_ancestor_arguments(this, i, result) }

        /** Gets any ancestor_arguments */
        AstNode getAAncestorArguments() { solidity_inheritance_specifier_ancestor_arguments(this, _, result) }

        /** Gets the number of ancestor_argumentss */
        int getNumAncestorArgumentss() { result = count(this.getAAncestorArguments()) }

        /** Gets the ancestor */
        AstNode getAncestor() { solidity_inheritance_specifier_ancestor(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getAAncestorArguments()
            or result = this.getAncestor()
        }

    }

    /** A `inline_array_expression` node in the AST */
    class InlineArrayExpression extends @solidity_inline_array_expression, AstNode {
        override string getAPrimaryQlClass() { result = "InlineArrayExpression" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_inline_array_expression_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `interface_declaration` node in the AST */
    class InterfaceDeclaration extends @solidity_interface_declaration, AstNode {
        override string getAPrimaryQlClass() { result = "InterfaceDeclaration" }

        /** Gets the body */
        AstNode getBody() { solidity_interface_declaration_body(this, 0, result) }

        /** Gets the name */
        AstNode getName() { solidity_interface_declaration_name(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_interface_declaration_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getBody()
            or result = this.getName()
        }

    }

    /** A `layout_specifier` node in the AST */
    class LayoutSpecifier extends @solidity_layout_specifier, AstNode {
        override string getAPrimaryQlClass() { result = "LayoutSpecifier" }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `library_declaration` node in the AST */
    class LibraryDeclaration extends @solidity_library_declaration, AstNode {
        override string getAPrimaryQlClass() { result = "LibraryDeclaration" }

        /** Gets the body */
        AstNode getBody() { solidity_library_declaration_body(this, 0, result) }

        /** Gets the name */
        AstNode getName() { solidity_library_declaration_name(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getBody()
            or result = this.getName()
        }

    }

    /** A `member_expression` node in the AST */
    class MemberExpression extends @solidity_member_expression, AstNode {
        override string getAPrimaryQlClass() { result = "MemberExpression" }

        /** Gets the object */
        AstNode getObject() { solidity_member_expression_object(this, 0, result) }

        /** Gets the property */
        AstNode getProperty() { solidity_member_expression_property(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getObject()
            or result = this.getProperty()
        }

    }

    /** A `meta_type_expression` node in the AST */
    class MetaTypeExpression extends @solidity_meta_type_expression, AstNode {
        override string getAPrimaryQlClass() { result = "MetaTypeExpression" }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `modifier_definition` node in the AST */
    class ModifierDefinition extends @solidity_modifier_definition, AstNode {
        override string getAPrimaryQlClass() { result = "ModifierDefinition" }

        /** Gets the name */
        AstNode getName() { solidity_modifier_definition_name(this, 0, result) }

        /** Gets the body */
        AstNode getBody() { solidity_modifier_definition_body(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_modifier_definition_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getName()
            or result = this.getBody()
        }

    }

    /** A `modifier_invocation` node in the AST */
    class ModifierInvocation extends @solidity_modifier_invocation, AstNode {
        override string getAPrimaryQlClass() { result = "ModifierInvocation" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_modifier_invocation_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `new_expression` node in the AST */
    class NewExpression extends @solidity_new_expression, AstNode {
        override string getAPrimaryQlClass() { result = "NewExpression" }

        /** Gets the name */
        AstNode getName() { solidity_new_expression_name(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_new_expression_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getName()
        }

    }

    /** A `number_literal` node in the AST */
    class NumberLiteral extends @solidity_number_literal, AstNode {
        override string getAPrimaryQlClass() { result = "NumberLiteral" }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `number_unit` node in the AST */
    class NumberUnit extends @solidity_number_unit, AstNode {
        override string getAPrimaryQlClass() { result = "NumberUnit" }

    }

    /** A `override_specifier` node in the AST */
    class OverrideSpecifier extends @solidity_override_specifier, AstNode {
        override string getAPrimaryQlClass() { result = "OverrideSpecifier" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_override_specifier_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `parameter` node in the AST */
    class Parameter extends @solidity_parameter, AstNode {
        override string getAPrimaryQlClass() { result = "Parameter" }

        /** Gets the type */
        AstNode getType() { solidity_parameter_type(this, 0, result) }

        /** Gets the storage_location */
        AstNode getStorageLocation() { solidity_parameter_location(this, 0, result) }

        /** Gets the name */
        AstNode getName() { solidity_parameter_name(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getType()
            or result = this.getStorageLocation()
            or result = this.getName()
        }

    }

    /** A `parenthesized_expression` node in the AST */
    class ParenthesizedExpression extends @solidity_parenthesized_expression, AstNode {
        override string getAPrimaryQlClass() { result = "ParenthesizedExpression" }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `payable_conversion_expression` node in the AST */
    class PayableConversionExpression extends @solidity_payable_conversion_expression, AstNode {
        override string getAPrimaryQlClass() { result = "PayableConversionExpression" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_payable_conversion_expression_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `pragma_directive` node in the AST */
    class PragmaDirective extends @solidity_pragma_directive, AstNode {
        override string getAPrimaryQlClass() { result = "PragmaDirective" }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `pragma_value` node in the AST */
    class PragmaValue extends @solidity_pragma_value, AstNode {
        override string getAPrimaryQlClass() { result = "PragmaValue" }

    }

    /** A `primitive_type` node in the AST */
    class PrimitiveType extends @solidity_primitive_type, AstNode {
        override string getAPrimaryQlClass() { result = "PrimitiveType" }

    }

    /** A `return_parameter` node in the AST */
    class ReturnParameter extends @solidity_return_parameter, AstNode {
        override string getAPrimaryQlClass() { result = "ReturnParameter" }

        /** Gets the storage_location */
        AstNode getStorageLocation() { solidity_return_parameter_location(this, 0, result) }

        /** Gets the type */
        AstNode getType() { solidity_return_parameter_type(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getStorageLocation()
            or result = this.getType()
        }

    }

    /** A `return_statement` node in the AST */
    class ReturnStatement extends @solidity_return_statement, AstNode {
        override string getAPrimaryQlClass() { result = "ReturnStatement" }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `return_type_definition` node in the AST */
    class ReturnTypeDefinition extends @solidity_return_type_definition, AstNode {
        override string getAPrimaryQlClass() { result = "ReturnTypeDefinition" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_return_type_definition_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `revert_arguments` node in the AST */
    class RevertArguments extends @solidity_revert_arguments, AstNode {
        override string getAPrimaryQlClass() { result = "RevertArguments" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_revert_arguments_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `revert_statement` node in the AST */
    class RevertStatement extends @solidity_revert_statement, AstNode {
        override string getAPrimaryQlClass() { result = "RevertStatement" }

        /** Gets the error */
        AstNode getError() { solidity_revert_statement_error(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getError()
        }

    }

    /** A `slice_access` node in the AST */
    class SliceAccess extends @solidity_slice_access, AstNode {
        override string getAPrimaryQlClass() { result = "SliceAccess" }

        /** Gets the to */
        AstNode getTo() { solidity_slice_access_to(this, 0, result) }

        /** Gets the base */
        AstNode getBase() { solidity_slice_access_base(this, 0, result) }

        /** Gets the from */
        AstNode getFrom() { solidity_slice_access_from(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getTo()
            or result = this.getBase()
            or result = this.getFrom()
        }

    }

    /** A `solidity_pragma_token` node in the AST */
    class SolidityPragmaToken extends @solidity_solidity_pragma_token, AstNode {
        override string getAPrimaryQlClass() { result = "SolidityPragmaToken" }

        /** Gets the version_constraint at index `i` */
        AstNode getVersionConstraint(int i) { solidity_solidity_pragma_token_version_constraint(this, i, result) }

        /** Gets any version_constraint */
        AstNode getAVersionConstraint() { solidity_solidity_pragma_token_version_constraint(this, _, result) }

        /** Gets the number of version_constraints */
        int getNumVersionConstraints() { result = count(this.getAVersionConstraint()) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getAVersionConstraint()
        }

    }

    /** A `solidity_version_comparison_operator` node in the AST */
    class SolidityVersionComparisonOperator extends @solidity_solidity_version_comparison_operator, AstNode {
        override string getAPrimaryQlClass() { result = "SolidityVersionComparisonOperator" }

    }

    /** A `source_file` node in the AST */
    class SourceFile extends @solidity_source_file, AstNode {
        override string getAPrimaryQlClass() { result = "SourceFile" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_source_file_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `state_location` node in the AST */
    class StateLocation extends @solidity_state_location, AstNode {
        override string getAPrimaryQlClass() { result = "StateLocation" }

    }

    /** A `state_mutability` node in the AST */
    class StateMutability extends @solidity_state_mutability, AstNode {
        override string getAPrimaryQlClass() { result = "StateMutability" }

    }

    /** A `state_variable_declaration` node in the AST */
    class StateVariableDeclaration extends @solidity_state_variable_declaration, AstNode {
        override string getAPrimaryQlClass() { result = "StateVariableDeclaration" }

        /** Gets the field_value */
        AstNode getFieldValue() { solidity_state_variable_declaration_value(this, 0, result) }

        /** Gets the type */
        AstNode getType() { solidity_state_variable_declaration_type(this, 0, result) }

        /** Gets the storage_location at index `i` */
        AstNode getStorageLocation(int i) { solidity_state_variable_declaration_location(this, i, result) }

        /** Gets any storage_location */
        AstNode getAStorageLocation() { solidity_state_variable_declaration_location(this, _, result) }

        /** Gets the number of storage_locations */
        int getNumStorageLocations() { result = count(this.getAStorageLocation()) }

        /** Gets the name */
        AstNode getName() { solidity_state_variable_declaration_name(this, 0, result) }

        /** Gets the visibility at index `i` */
        AstNode getVisibility(int i) { solidity_state_variable_declaration_visibility(this, i, result) }

        /** Gets any visibility */
        AstNode getAVisibility() { solidity_state_variable_declaration_visibility(this, _, result) }

        /** Gets the number of visibilitys */
        int getNumVisibilitys() { result = count(this.getAVisibility()) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_state_variable_declaration_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getFieldValue()
            or result = this.getType()
            or result = this.getAStorageLocation()
            or result = this.getName()
            or result = this.getAVisibility()
        }

    }

    /** A `statement` node in the AST */
    class Statement extends @solidity_statement, AstNode {
        override string getAPrimaryQlClass() { result = "Statement" }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `string` node in the AST */
    class String extends @solidity_string, AstNode {
        override string getAPrimaryQlClass() { result = "String" }

    }

    /** A `string_literal` node in the AST */
    class StringLiteral extends @solidity_string_literal, AstNode {
        override string getAPrimaryQlClass() { result = "StringLiteral" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_string_literal_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `struct_body` node in the AST */
    class StructBody extends @solidity_struct_body, AstNode {
        override string getAPrimaryQlClass() { result = "StructBody" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_struct_body_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `struct_declaration` node in the AST */
    class StructDeclaration extends @solidity_struct_declaration, AstNode {
        override string getAPrimaryQlClass() { result = "StructDeclaration" }

        /** Gets the name */
        AstNode getName() { solidity_struct_declaration_name(this, 0, result) }

        /** Gets the body */
        AstNode getBody() { solidity_struct_declaration_body(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getName()
            or result = this.getBody()
        }

    }

    /** A `struct_expression` node in the AST */
    class StructExpression extends @solidity_struct_expression, AstNode {
        override string getAPrimaryQlClass() { result = "StructExpression" }

        /** Gets the type */
        AstNode getType() { solidity_struct_expression_type(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_struct_expression_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getType()
        }

    }

    /** A `struct_field_assignment` node in the AST */
    class StructFieldAssignment extends @solidity_struct_field_assignment, AstNode {
        override string getAPrimaryQlClass() { result = "StructFieldAssignment" }

        /** Gets the field_value */
        AstNode getFieldValue() { solidity_struct_field_assignment_value(this, 0, result) }

        /** Gets the name */
        AstNode getName() { solidity_struct_field_assignment_name(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getFieldValue()
            or result = this.getName()
        }

    }

    /** A `struct_member` node in the AST */
    class StructMember extends @solidity_struct_member, AstNode {
        override string getAPrimaryQlClass() { result = "StructMember" }

        /** Gets the type */
        AstNode getType() { solidity_struct_member_type(this, 0, result) }

        /** Gets the name */
        AstNode getName() { solidity_struct_member_name(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getType()
            or result = this.getName()
        }

    }

    /** A `ternary_expression` node in the AST */
    class TernaryExpression extends @solidity_ternary_expression, AstNode {
        override string getAPrimaryQlClass() { result = "TernaryExpression" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_ternary_expression_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `true` node in the AST */
    class True extends @solidity_true, AstNode {
        override string getAPrimaryQlClass() { result = "True" }

    }

    /** A `try_statement` node in the AST */
    class TryStatement extends @solidity_try_statement, AstNode {
        override string getAPrimaryQlClass() { result = "TryStatement" }

        /** Gets the body */
        AstNode getBody() { solidity_try_statement_body(this, 0, result) }

        /** Gets the attempt */
        AstNode getAttempt() { solidity_try_statement_attempt(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_try_statement_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getBody()
            or result = this.getAttempt()
        }

    }

    /** A `tuple_expression` node in the AST */
    class TupleExpression extends @solidity_tuple_expression, AstNode {
        override string getAPrimaryQlClass() { result = "TupleExpression" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_tuple_expression_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `type_alias` node in the AST */
    class TypeAlias extends @solidity_type_alias, AstNode {
        override string getAPrimaryQlClass() { result = "TypeAlias" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_type_alias_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `type_cast_expression` node in the AST */
    class TypeCastExpression extends @solidity_type_cast_expression, AstNode {
        override string getAPrimaryQlClass() { result = "TypeCastExpression" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_type_cast_expression_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `type_name` node in the AST */
    class TypeName extends @solidity_type_name, AstNode {
        override string getAPrimaryQlClass() { result = "TypeName" }

        /** Gets the key_identifier */
        AstNode getKeyIdentifier() { solidity_type_name_key_identifier(this, 0, result) }

        /** Gets the parameters at index `i` */
        AstNode getParameters(int i) { solidity_type_name_parameters(this, i, result) }

        /** Gets any parameters */
        AstNode getAParameters() { solidity_type_name_parameters(this, _, result) }

        /** Gets the number of parameterss */
        int getNumParameterss() { result = count(this.getAParameters()) }

        /** Gets the key_type */
        AstNode getKeyType() { solidity_type_name_key_type(this, 0, result) }

        /** Gets the value_identifier */
        AstNode getValueIdentifier() { solidity_type_name_value_identifier(this, 0, result) }

        /** Gets the value_type */
        AstNode getValueType() { solidity_type_name_value_type(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_type_name_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getKeyIdentifier()
            or result = this.getAParameters()
            or result = this.getKeyType()
            or result = this.getValueIdentifier()
            or result = this.getValueType()
        }

    }

    /** A `unary_expression` node in the AST */
    class UnaryExpression extends @solidity_unary_expression, AstNode {
        override string getAPrimaryQlClass() { result = "UnaryExpression" }

        /** Gets the argument */
        AstNode getArgument() { solidity_unary_expression_argument(this, 0, result) }

        /** Gets the operator */
        AstNode getOperator() { solidity_unary_expression_operator(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getArgument()
            or result = this.getOperator()
        }

    }

    /** A `unicode_string_literal` node in the AST */
    class UnicodeStringLiteral extends @solidity_unicode_string_literal, AstNode {
        override string getAPrimaryQlClass() { result = "UnicodeStringLiteral" }

    }

    /** A `update_expression` node in the AST */
    class UpdateExpression extends @solidity_update_expression, AstNode {
        override string getAPrimaryQlClass() { result = "UpdateExpression" }

        /** Gets the operator */
        AstNode getOperator() { solidity_update_expression_operator(this, 0, result) }

        /** Gets the argument */
        AstNode getArgument() { solidity_update_expression_argument(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getOperator()
            or result = this.getArgument()
        }

    }

    /** A `user_definable_operator` node in the AST */
    class UserDefinableOperator extends @solidity_user_definable_operator, AstNode {
        override string getAPrimaryQlClass() { result = "UserDefinableOperator" }

    }

    /** A `user_defined_type` node in the AST */
    class UserDefinedType extends @solidity_user_defined_type, AstNode {
        override string getAPrimaryQlClass() { result = "UserDefinedType" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_user_defined_type_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `user_defined_type_definition` node in the AST */
    class UserDefinedTypeDefinition extends @solidity_user_defined_type_definition, AstNode {
        override string getAPrimaryQlClass() { result = "UserDefinedTypeDefinition" }

        /** Gets the name */
        AstNode getName() { solidity_user_defined_type_definition_name(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getName()
        }

    }

    /** A `using_alias` node in the AST */
    class UsingAlias extends @solidity_using_alias, AstNode {
        override string getAPrimaryQlClass() { result = "UsingAlias" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_using_alias_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `using_directive` node in the AST */
    class UsingDirective extends @solidity_using_directive, AstNode {
        override string getAPrimaryQlClass() { result = "UsingDirective" }

        /** Gets the source */
        AstNode getSource() { solidity_using_directive_source(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_using_directive_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getSource()
        }

    }

    /** A `variable_declaration` node in the AST */
    class VariableDeclaration extends @solidity_variable_declaration, AstNode {
        override string getAPrimaryQlClass() { result = "VariableDeclaration" }

        /** Gets the name */
        AstNode getName() { solidity_variable_declaration_name(this, 0, result) }

        /** Gets the type */
        AstNode getType() { solidity_variable_declaration_type(this, 0, result) }

        /** Gets the storage_location */
        AstNode getStorageLocation() { solidity_variable_declaration_location(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getName()
            or result = this.getType()
            or result = this.getStorageLocation()
        }

    }

    /** A `variable_declaration_statement` node in the AST */
    class VariableDeclarationStatement extends @solidity_variable_declaration_statement, AstNode {
        override string getAPrimaryQlClass() { result = "VariableDeclarationStatement" }

        /** Gets the field_value */
        AstNode getFieldValue() { solidity_variable_declaration_statement_value(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getFieldValue()
        }

    }

    /** A `variable_declaration_tuple` node in the AST */
    class VariableDeclarationTuple extends @solidity_variable_declaration_tuple, AstNode {
        override string getAPrimaryQlClass() { result = "VariableDeclarationTuple" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_variable_declaration_tuple_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `visibility` node in the AST */
    class Visibility extends @solidity_visibility, AstNode {
        override string getAPrimaryQlClass() { result = "Visibility" }

    }

    /** A `while_statement` node in the AST */
    class WhileStatement extends @solidity_while_statement, AstNode {
        override string getAPrimaryQlClass() { result = "WhileStatement" }

        /** Gets the body */
        AstNode getBody() { solidity_while_statement_body(this, 0, result) }

        /** Gets the condition */
        AstNode getCondition() { solidity_while_statement_condition(this, 0, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getBody()
            or result = this.getCondition()
        }

    }

    /** A `yul_assignment` node in the AST */
    class YulAssignment extends @solidity_yul_assignment, AstNode {
        override string getAPrimaryQlClass() { result = "YulAssignment" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_yul_assignment_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `yul_block` node in the AST */
    class YulBlock extends @solidity_yul_block, AstNode {
        override string getAPrimaryQlClass() { result = "YulBlock" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_yul_block_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `yul_boolean` node in the AST */
    class YulBoolean extends @solidity_yul_boolean, AstNode {
        override string getAPrimaryQlClass() { result = "YulBoolean" }

    }

    /** A `yul_break` node in the AST */
    class YulBreak extends @solidity_yul_break, AstNode {
        override string getAPrimaryQlClass() { result = "YulBreak" }

    }

    /** A `yul_continue` node in the AST */
    class YulContinue extends @solidity_yul_continue, AstNode {
        override string getAPrimaryQlClass() { result = "YulContinue" }

    }

    /** A `yul_evm_builtin` node in the AST */
    class YulEvmBuiltin extends @solidity_yul_evm_builtin, AstNode {
        override string getAPrimaryQlClass() { result = "YulEvmBuiltin" }

    }

    /** A `yul_for_statement` node in the AST */
    class YulForStatement extends @solidity_yul_for_statement, AstNode {
        override string getAPrimaryQlClass() { result = "YulForStatement" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_yul_for_statement_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `yul_function_call` node in the AST */
    class YulFunctionCall extends @solidity_yul_function_call, AstNode {
        override string getAPrimaryQlClass() { result = "YulFunctionCall" }

        /** Gets the function */
        AstNode getFunction() { solidity_yul_function_call_function(this, 0, result) }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_yul_function_call_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getFunction()
        }

    }

    /** A `yul_function_definition` node in the AST */
    class YulFunctionDefinition extends @solidity_yul_function_definition, AstNode {
        override string getAPrimaryQlClass() { result = "YulFunctionDefinition" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_yul_function_definition_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `yul_hex_string_literal` node in the AST */
    class YulHexStringLiteral extends @solidity_yul_hex_string_literal, AstNode {
        override string getAPrimaryQlClass() { result = "YulHexStringLiteral" }

    }

    /** A `yul_identifier` node in the AST */
    class YulIdentifier extends @solidity_yul_identifier, AstNode {
        override string getAPrimaryQlClass() { result = "YulIdentifier" }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `yul_if_statement` node in the AST */
    class YulIfStatement extends @solidity_yul_if_statement, AstNode {
        override string getAPrimaryQlClass() { result = "YulIfStatement" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_yul_if_statement_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `yul_label` node in the AST */
    class YulLabel extends @solidity_yul_label, AstNode {
        override string getAPrimaryQlClass() { result = "YulLabel" }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `yul_path` node in the AST */
    class YulPath extends @solidity_yul_path, AstNode {
        override string getAPrimaryQlClass() { result = "YulPath" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_yul_path_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `yul_string_literal` node in the AST */
    class YulStringLiteral extends @solidity_yul_string_literal, AstNode {
        override string getAPrimaryQlClass() { result = "YulStringLiteral" }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `yul_switch_statement` node in the AST */
    class YulSwitchStatement extends @solidity_yul_switch_statement, AstNode {
        override string getAPrimaryQlClass() { result = "YulSwitchStatement" }

        /** Gets the child at index `i` */
        override AstNode getChild(int i) { solidity_yul_switch_statement_child(this, i, result) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
        }

    }

    /** A `yul_variable_declaration` node in the AST */
    class YulVariableDeclaration extends @solidity_yul_variable_declaration, AstNode {
        override string getAPrimaryQlClass() { result = "YulVariableDeclaration" }

        /** Gets the right */
        AstNode getRight() { solidity_yul_variable_declaration_right(this, 0, result) }

        /** Gets the left at index `i` */
        AstNode getLeft(int i) { solidity_yul_variable_declaration_left(this, i, result) }

        /** Gets any left */
        AstNode getALeft() { solidity_yul_variable_declaration_left(this, _, result) }

        /** Gets the number of lefts */
        int getNumLefts() { result = count(this.getALeft()) }

        override AstNode getAFieldOrChild() {
            result = super.getAFieldOrChild()
            or result = this.getRight()
            or result = this.getALeft()
        }

    }

    /** A `comment` node in the AST */
    class Comment extends @solidity_comment, AstNode {
        override string getAPrimaryQlClass() { result = "Comment" }

    }

    /** A `enum_value` node in the AST */
    class EnumValue extends @solidity_enum_value, AstNode {
        override string getAPrimaryQlClass() { result = "EnumValue" }

    }

    /** A `identifier` node in the AST */
    class Identifier extends @solidity_identifier, AstNode {
        override string getAPrimaryQlClass() { result = "Identifier" }

    }

    /** A `immutable` node in the AST */
    class Immutable extends @solidity_immutable, AstNode {
        override string getAPrimaryQlClass() { result = "Immutable" }

    }

    /** A `solidity_version` node in the AST */
    class SolidityVersion extends @solidity_solidity_version, AstNode {
        override string getAPrimaryQlClass() { result = "SolidityVersion" }

    }

    /** A `unchecked` node in the AST */
    class Unchecked extends @solidity_unchecked, AstNode {
        override string getAPrimaryQlClass() { result = "Unchecked" }

    }

    /** A `virtual` node in the AST */
    class Virtual extends @solidity_virtual, AstNode {
        override string getAPrimaryQlClass() { result = "Virtual" }

    }

    /** A `yul_decimal_number` node in the AST */
    class YulDecimalNumber extends @solidity_yul_decimal_number, AstNode {
        override string getAPrimaryQlClass() { result = "YulDecimalNumber" }

    }

    /** A `yul_hex_number` node in the AST */
    class YulHexNumber extends @solidity_yul_hex_number, AstNode {
        override string getAPrimaryQlClass() { result = "YulHexNumber" }

    }

    /** A `yul_leave` node in the AST */
    class YulLeave extends @solidity_yul_leave, AstNode {
        override string getAPrimaryQlClass() { result = "YulLeave" }

    }

}
