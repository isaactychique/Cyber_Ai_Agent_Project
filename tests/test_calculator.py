import pytest

from sentinel.tools.calculator import calculate


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("25 * 4", 100),
        ("(8 + 4) / 3", 4),
        ("-5 + 2", -3),
        ("2 ** 3", 8),
    ],
)
def test_calculate_supported_arithmetic(expression, expected):
    assert calculate(expression) == expected


@pytest.mark.parametrize(
    "expression",
    [
        "__import__('os').system('whoami')",
        "2 ** 11",
        "1e999",
        "9999999999999",
        "1 + " + "1 + " * 25 + "1",
    ],
)
def test_calculate_rejects_unsafe_or_out_of_range_expressions(expression):
    with pytest.raises(ValueError):
        calculate(expression)


def test_calculate_division_by_zero_raises():
    with pytest.raises(ZeroDivisionError):
        calculate("1 / 0")
