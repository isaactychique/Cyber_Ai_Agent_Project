import ast 
import math
import operator 

operators = {
    ast.Add : operator.add, 
    ast.Sub : operator.sub,
    ast.Mult : operator.mul, 
    ast.Div : operator.truediv,
    ast.Pow : operator.pow,
    ast.USub : operator.neg,
    ast.UAdd : operator.pos,
}

def calculate( expression :str ) -> float : 
    """
        Evaluate a restricted arithmetic expression. 
        No eval() or arbitrary Python execution 
    """
    if len(expression) > 100 : 
        raise ValueError("Expression too long")
    
    tree = ast.parse(expression, mode = "eval")


    def evaluate(node) :
        if isinstance(node, ast.Constant) : 
            if type(node.value) not in (int, float) : 
                raise ValueError("Only numbers are allowed")
            if not math.isfinite(node.value) or abs(node.value) > 1e12:
                raise ValueError("Number out of range")
            return node.value 

        if isinstance(node, ast.BinOp):
            operator_type = type(node.op)

            if operator_type not in operators: 
                raise ValueError("Operator not allowed")

            left = evaluate(node.left)
            right = evaluate(node.right)

            if operator_type is ast.Pow and abs(right) > 10 :
                raise ValueError("Exponent too large")
            
            result = operators[operator_type](left, right)

            if not math.isfinite(result) or abs(result) > 1e12 : 
                raise ValueError("Result too large")

            return result
        
        if isinstance(node, ast.UnaryOp) : 
            operator_type = type(node.op)

            if operator_type not in operators:
                raise ValueError("Unary operator not allowed")

            return operators[operator_type](evaluate(node.operand))

        raise ValueError("Expression contains forbidden syntax")

    return evaluate(tree.body)
