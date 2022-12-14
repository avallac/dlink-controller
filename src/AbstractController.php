<?php

namespace Avallac\DlinkController;

abstract class AbstractController
{
    protected $count = 0;
    protected $result = [];

    protected function startTest(string $name)
    {
        $this->count++;
        $this->result[$this->count]['name'] = $name;
        $this->result[$this->count]['error'] = [];
        $this->result[$this->count]['result'] = null;
    }

    protected function resultTest(bool $result)
    {
        $this->result[$this->count]['result'] = $result;
    }

    protected function addError(string $error, $context)
    {
        $this->result[$this->count]['error'][] = [$error, $context];
    }
}