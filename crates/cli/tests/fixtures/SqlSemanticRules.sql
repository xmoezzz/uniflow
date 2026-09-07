PROCEDURE transaction_owner IS BEGIN COMMIT; END;
SELECT name FROM employee;
CREATE PACKAGE pkg IS CURSOR cur IS SELECT dummy FROM dual; END;
BEGIN RAISE my_error; log('never'); END;
-- %test(sample)
-- %disabled
PROCEDURE disabled_test;
SELECT DISTINCT item.name FROM item ORDER BY item.group_id;
IF NOT cur%FOUND THEN work; END IF;
BEGIN broken_call(1; END;
BEGIN SELECT name INTO value FROM employee; END;
BEGIN RAISE TOO_MANY_ROWS; END;
BEGIN ut.expect(actual).to_equal(actual); END;
BEGIN work; EXCEPTION WHEN TOO_MANY_ROWS THEN NULL; END;
DECLARE custom_error EXCEPTION; BEGIN RAISE custom_error; END;
SELECT a.id FROM employee a;
DECLARE CURSOR unused_cur IS SELECT id FROM employee; BEGIN work; END;
PROCEDURE unused_param(a IN NUMBER, b IN NUMBER) IS BEGIN compute(a); END;
DECLARE unused_value NUMBER; BEGIN work; END;
DECLARE hidden_value NUMBER; BEGIN DECLARE hidden_value VARCHAR2(5); BEGIN work; END; END;
DECLARE local_id NUMBER; BEGIN SELECT COUNT(local_id) INTO total FROM employee; END;
DECLARE trailing_name_ VARCHAR2(20); BEGIN work; END;
