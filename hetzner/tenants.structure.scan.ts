import * as ts from 'typescript';

export type ReasonCode =
  'forbidden-constructor' | 'unresolved-constructor' | 'host-count' | 'host-gate' | 'route-gate';

/**
 * The only members `new` may construct, by module. Host is counted and gate-checked
 * separately, and so is NetworkRoute. StackReference reads another stack's outputs
 * and registers no provider resource.
 */
const ALLOWED_MEMBERS: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ['@pulumi/hcloud', new Set(['Network', 'NetworkSubnet', 'NetworkRoute'])],
  ['@pulumi/pulumi', new Set(['Config', 'StackReference'])],
  ['@branchleft/hetzner-host', new Set(['Host'])],
]);

/** The number of `new Host(...)` the program declares: edge-t, and db-t1 and app-t1 each behind its switch. */
export const EXPECTED_HOST_COUNT = 3;

const HOST_MODULE = '@branchleft/hetzner-host';
const ROUTE_MODULE = '@pulumi/hcloud';
const ROUTE_MEMBER = 'NetworkRoute';
const VERIFY_NAME = 'verified';
const NETWORK_ID_KEY = 'networkId';
const GATE_NAME = 'gateRegistration';
const TRANSFORMATIONS_KEY = 'transformations';

interface NamespaceValue {
  readonly kind: 'namespace';
  readonly module: string;
}

interface MemberValue {
  readonly kind: 'member';
  readonly module: string;
  readonly member: string;
}

type ModuleValue = NamespaceValue | MemberValue;

type Binding =
  | { readonly kind: 'imported'; readonly value: ModuleValue }
  | { readonly kind: 'alias'; readonly initializer: ts.Expression }
  | { readonly kind: 'destructured'; readonly source: ts.Expression; readonly key: string };

interface NamedBinding {
  readonly name: string;
  readonly binding: Binding;
}

/** Every declared name in the file at any scope, and the few forms that can be followed to a module value. */
interface DeclarationIndex {
  readonly declarations: Map<string, ts.Node[]>;
  readonly bindings: Map<string, Binding>;
}

type Construction =
  'allowed' | 'host' | 'route' | 'forbidden-constructor' | 'unresolved-constructor';

const DECLARING_KINDS: ReadonlySet<ts.SyntaxKind> = new Set([
  ts.SyntaxKind.VariableDeclaration,
  ts.SyntaxKind.Parameter,
  ts.SyntaxKind.BindingElement,
  ts.SyntaxKind.FunctionDeclaration,
  ts.SyntaxKind.FunctionExpression,
  ts.SyntaxKind.ClassDeclaration,
  ts.SyntaxKind.ClassExpression,
  ts.SyntaxKind.EnumDeclaration,
  ts.SyntaxKind.InterfaceDeclaration,
  ts.SyntaxKind.TypeAliasDeclaration,
  ts.SyntaxKind.TypeParameter,
  ts.SyntaxKind.ModuleDeclaration,
  ts.SyntaxKind.ImportEqualsDeclaration,
  ts.SyntaxKind.ImportClause,
  ts.SyntaxKind.NamespaceImport,
  ts.SyntaxKind.ImportSpecifier,
]);

function isSingleConstList(node: ts.Node): boolean {
  return (
    ts.isVariableDeclarationList(node) &&
    node.declarations.length === 1 &&
    (node.flags & ts.NodeFlags.BlockScoped) === ts.NodeFlags.Const
  );
}

function recognisedModule(declaration: ts.Node): string | undefined {
  if (!ts.isImportDeclaration(declaration)) {
    return undefined;
  }
  const { moduleSpecifier, importClause } = declaration;
  if (
    !ts.isStringLiteral(moduleSpecifier) ||
    importClause === undefined ||
    importClause.isTypeOnly
  ) {
    return undefined;
  }
  return ALLOWED_MEMBERS.has(moduleSpecifier.text) ? moduleSpecifier.text : undefined;
}

function namespaceImportBinding(node: ts.NamespaceImport): NamedBinding | undefined {
  const module = recognisedModule(node.parent.parent);
  if (module === undefined) {
    return undefined;
  }
  return {
    name: node.name.text,
    binding: { kind: 'imported', value: { kind: 'namespace', module } },
  };
}

function namedImportBinding(node: ts.ImportSpecifier): NamedBinding | undefined {
  const module = recognisedModule(node.parent.parent.parent);
  if (module === undefined || node.isTypeOnly) {
    return undefined;
  }
  const member = (node.propertyName ?? node.name).text;
  return {
    name: node.name.text,
    binding: { kind: 'imported', value: { kind: 'member', module, member } },
  };
}

function constAliasBinding(node: ts.VariableDeclaration): NamedBinding | undefined {
  if (
    !ts.isIdentifier(node.name) ||
    node.initializer === undefined ||
    !isSingleConstList(node.parent)
  ) {
    return undefined;
  }
  return { name: node.name.text, binding: { kind: 'alias', initializer: node.initializer } };
}

function isPlainElement(element: ts.BindingElement): boolean {
  return (
    ts.isIdentifier(element.name) &&
    element.initializer === undefined &&
    element.dotDotDotToken === undefined &&
    (element.propertyName === undefined || ts.isIdentifier(element.propertyName))
  );
}

function destructuredBinding(element: ts.BindingElement): NamedBinding | undefined {
  const declaration = element.parent.parent;
  if (
    !ts.isObjectBindingPattern(element.parent) ||
    !ts.isVariableDeclaration(declaration) ||
    declaration.initializer === undefined ||
    !isSingleConstList(declaration.parent) ||
    !isPlainElement(element)
  ) {
    return undefined;
  }
  const key = element.propertyName ?? element.name;
  if (!ts.isIdentifier(key) || !ts.isIdentifier(element.name)) {
    return undefined;
  }
  return {
    name: element.name.text,
    binding: { kind: 'destructured', source: declaration.initializer, key: key.text },
  };
}

function bindingFor(node: ts.Node): NamedBinding | undefined {
  if (ts.isNamespaceImport(node)) {
    return namespaceImportBinding(node);
  }
  if (ts.isImportSpecifier(node)) {
    return namedImportBinding(node);
  }
  if (ts.isVariableDeclaration(node)) {
    return constAliasBinding(node);
  }
  if (ts.isBindingElement(node)) {
    return destructuredBinding(node);
  }
  return undefined;
}

function recordDeclaration(node: ts.Node, index: DeclarationIndex): void {
  if (!DECLARING_KINDS.has(node.kind)) {
    return;
  }
  const { name } = node as ts.NamedDeclaration;
  if (name === undefined || !ts.isIdentifier(name)) {
    return;
  }
  index.declarations.set(name.text, [...(index.declarations.get(name.text) ?? []), node]);
}

function buildIndex(sourceFile: ts.SourceFile): DeclarationIndex {
  const index: DeclarationIndex = { declarations: new Map(), bindings: new Map() };
  const visit = (node: ts.Node): void => {
    recordDeclaration(node, index);
    const named = bindingFor(node);
    if (named !== undefined) {
      index.bindings.set(named.name, named.binding);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return index;
}

function unwrap(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isSatisfiesExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isNonNullExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

interface MemberAccess {
  readonly object: ts.Expression;
  readonly key: string;
}

function memberAccessOf(expression: ts.Expression): MemberAccess | undefined {
  if (
    ts.isPropertyAccessExpression(expression) &&
    expression.questionDotToken === undefined &&
    ts.isIdentifier(expression.name)
  ) {
    return { object: expression.expression, key: expression.name.text };
  }
  if (
    ts.isElementAccessExpression(expression) &&
    expression.questionDotToken === undefined &&
    ts.isStringLiteral(expression.argumentExpression)
  ) {
    return { object: expression.expression, key: expression.argumentExpression.text };
  }
  return undefined;
}

function resolveMember(
  access: MemberAccess,
  index: DeclarationIndex,
  seen: ReadonlySet<string>
): MemberValue | undefined {
  const owner = resolveExpression(access.object, index, seen);
  return owner?.kind === 'namespace'
    ? { kind: 'member', module: owner.module, member: access.key }
    : undefined;
}

function resolveBinding(
  binding: Binding,
  index: DeclarationIndex,
  seen: ReadonlySet<string>
): ModuleValue | undefined {
  if (binding.kind === 'imported') {
    return binding.value;
  }
  if (binding.kind === 'alias') {
    return resolveExpression(binding.initializer, index, seen);
  }
  return resolveMember({ object: binding.source, key: binding.key }, index, seen);
}

function resolveIdentifier(
  name: string,
  index: DeclarationIndex,
  seen: ReadonlySet<string>
): ModuleValue | undefined {
  const binding = index.bindings.get(name);
  if (seen.has(name) || index.declarations.get(name)?.length !== 1 || binding === undefined) {
    return undefined;
  }
  return resolveBinding(binding, index, new Set([...seen, name]));
}

function resolveExpression(
  expression: ts.Expression,
  index: DeclarationIndex,
  seen: ReadonlySet<string>
): ModuleValue | undefined {
  const inner = unwrap(expression);
  if (ts.isIdentifier(inner)) {
    return resolveIdentifier(inner.text, index, seen);
  }
  const access = memberAccessOf(inner);
  return access === undefined ? undefined : resolveMember(access, index, seen);
}

function classifyConstruction(node: ts.NewExpression, index: DeclarationIndex): Construction {
  const value = resolveExpression(node.expression, index, new Set());
  if (value?.kind !== 'member') {
    return 'unresolved-constructor';
  }
  if (ALLOWED_MEMBERS.get(value.module)?.has(value.member) !== true) {
    return 'forbidden-constructor';
  }
  if (value.module === ROUTE_MODULE && value.member === ROUTE_MEMBER) {
    return 'route';
  }
  return value.module === HOST_MODULE ? 'host' : 'allowed';
}

function propertyKeyText(property: ts.ObjectLiteralElementLike): string | undefined {
  const { name } = property;
  if (name === undefined) {
    return undefined;
  }
  return ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)
    ? name.text
    : undefined;
}

function soleTransformations(options: ts.ObjectLiteralExpression): ts.Expression | undefined {
  const keys = options.properties.map(propertyKeyText);
  if (keys.includes(undefined)) {
    return undefined;
  }
  const matching = options.properties.filter(
    (_property, position) => keys[position] === TRANSFORMATIONS_KEY
  );
  const [only] = matching;
  if (matching.length !== 1 || only === undefined) {
    return undefined;
  }
  return ts.isPropertyAssignment(only) && ts.isIdentifier(only.name) ? only.initializer : undefined;
}

function isTopLevelExportedConst(node: ts.Node): boolean {
  if (!ts.isVariableDeclaration(node) || !isSingleConstList(node.parent)) {
    return false;
  }
  const statement = node.parent.parent;
  return (
    ts.isVariableStatement(statement) &&
    ts.isSourceFile(statement.parent) &&
    statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) === true
  );
}

function isRealGate(index: DeclarationIndex): boolean {
  const declarations = index.declarations.get(GATE_NAME) ?? [];
  const [declaration] = declarations;
  return (
    declarations.length === 1 && declaration !== undefined && isTopLevelExportedConst(declaration)
  );
}

function isGatedHost(host: ts.NewExpression, index: DeclarationIndex): boolean {
  const args = host.arguments ?? [];
  const options = args[1];
  if (
    args.some(ts.isSpreadElement) ||
    options === undefined ||
    !ts.isObjectLiteralExpression(options)
  ) {
    return false;
  }
  const transformations = soleTransformations(options);
  return (
    transformations !== undefined &&
    ts.isArrayLiteralExpression(transformations) &&
    transformations.elements.some(
      (element) => ts.isIdentifier(element) && element.text === GATE_NAME
    ) &&
    isRealGate(index)
  );
}

function describeViolation(code: ReasonCode, node: ts.Node, sourceFile: ts.SourceFile): string {
  const line = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
  const [firstLine = ''] = node.getText(sourceFile).split('\n');
  return `${code} line ${line}: ${firstLine.trimEnd()}`;
}

/**
 * A route is gated when its props are an object literal whose single `networkId`
 * is a call of the file's own `verified` (possibly followed by `.apply(...)`),
 * with no spread after it that could replace it. An ungated route is created
 * even when the project check refuses.
 */
function isGatedRoute(route: ts.NewExpression, index: DeclarationIndex): boolean {
  const args = route.arguments ?? [];
  const props = args[1];
  if (
    args.some(ts.isSpreadElement) ||
    props === undefined ||
    !ts.isObjectLiteralExpression(props)
  ) {
    return false;
  }
  const keys = props.properties.map(propertyKeyText);
  const positions = props.properties.flatMap((property, position) =>
    ts.isSpreadAssignment(property) ? [] : keys[position] === NETWORK_ID_KEY ? [position] : []
  );
  const [position] = positions;
  const entry = position === undefined ? undefined : props.properties[position];
  if (
    positions.length !== 1 ||
    position === undefined ||
    entry === undefined ||
    !ts.isPropertyAssignment(entry) ||
    props.properties.some((property, at) => at > position && ts.isSpreadAssignment(property)) ||
    props.properties.some(
      (property, at) => !ts.isSpreadAssignment(property) && keys[at] === undefined
    )
  ) {
    return false;
  }
  let current = unwrap(entry.initializer);
  while (
    ts.isCallExpression(current) &&
    ts.isPropertyAccessExpression(current.expression) &&
    current.expression.name.text === 'apply'
  ) {
    current = unwrap(current.expression.expression);
  }
  return (
    ts.isCallExpression(current) &&
    ts.isIdentifier(current.expression) &&
    current.expression.text === VERIFY_NAME &&
    current.arguments.length === 1 &&
    index.declarations.get(VERIFY_NAME)?.length === 1 &&
    index.bindings.has(VERIFY_NAME)
  );
}

function describeHostViolations(
  hosts: readonly ts.NewExpression[],
  index: DeclarationIndex,
  sourceFile: ts.SourceFile
): string[] {
  const messages: string[] = [];
  if (hosts.length === 0) {
    messages.push(
      `host-count line 1: expected exactly ${EXPECTED_HOST_COUNT} new Host(...), found none`
    );
  } else if (hosts.length !== EXPECTED_HOST_COUNT) {
    messages.push(...hosts.map((host) => describeViolation('host-count', host, sourceFile)));
  }
  messages.push(
    ...hosts
      .filter((host) => !isGatedHost(host, index))
      .map((host) => describeViolation('host-gate', host, sourceFile))
  );
  return messages;
}

function collectNewExpressions(sourceFile: ts.SourceFile): ts.NewExpression[] {
  const found: ts.NewExpression[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isNewExpression(node)) {
      found.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return found;
}

/**
 * Reads TypeScript source text and returns one message per violation: a `new`
 * of anything but Network, NetworkSubnet, NetworkRoute, Config, StackReference
 * or Host; a route whose network id is not gated by `verified`; or a Host count
 * that is not exactly EXPECTED_HOST_COUNT, or a Host without the gate. Parses only.
 */
export function scanTenantsSource(text: string): string[] {
  const sourceFile = ts.createSourceFile(
    'tenants.ts',
    text,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS
  );
  const index = buildIndex(sourceFile);
  const messages: string[] = [];
  const hosts: ts.NewExpression[] = [];
  for (const node of collectNewExpressions(sourceFile)) {
    const construction = classifyConstruction(node, index);
    if (construction === 'host') {
      hosts.push(node);
    } else if (construction === 'route') {
      if (!isGatedRoute(node, index)) {
        messages.push(describeViolation('route-gate', node, sourceFile));
      }
    } else if (construction !== 'allowed') {
      messages.push(describeViolation(construction, node, sourceFile));
    }
  }
  return [...messages, ...describeHostViolations(hosts, index, sourceFile)];
}
