function assign(target, input) {
    Object.assign(target, JSON.parse(input));
    Object.assign(target, JSON.parse('{"fixed": true}'));
}
