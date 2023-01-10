#!/usr/bin/env php
<?php

require __DIR__ . '/../vendor/autoload.php';

if (empty($argv[1])) {
    print "Usage:\n";
    print "dgs121010mp_checker.php IP Password";
}

$yaml = file_get_contents(__DIR__ . '/../config.yaml');
if (empty($yaml)) {
    print "Конфигурационный файл config.yaml не найден";
    exit;
}
$config = \Symfony\Component\Yaml\Yaml::parse($yaml);
$update = $config['config']['UPDATE'] ?? false;
$update = $update === true;

$ip = $argv[1];
$dev = new \Avallac\DlinkController\DGS121010MP($ip, $config['config'], $argv[2]);
print "Старт проверки \033[36m$ip\033[0m\n";
$result = $dev->check($update);
$errors = 0;

foreach ($result as $item) {
    print "\033[33m" . $item['name'] . "\033[0m - " . ($item['result'] ? 'OK' : "\033[31mKO\033[0m") . "\n";
    foreach ($item['error'] as $line) {
        $errors++;
        print "-> \033[31m" .  $line[0] . "\033[0m\n";
    }
}

return exit((int)!empty($errors));