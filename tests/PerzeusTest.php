<?php

require './vendor/autoload.php';

use VeeeneX\Perzeus;

class PerzeusTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->Perzeus = new Perzeus();
    }

    public function testValid()
    {
        for ($i = 0; $i < 10; $i++) {
        	$password = $this->getRandomString(25);

        	$Hash = $this->Perzeus->createHash($password);
        	$valid = $this->Perzeus->validatePassword($password, $Hash->hash, $Hash->rand);
            $this->assertTrue($valid);
        }
    }

    public function testInValid()
    {
        for ($i = 0; $i < 10; $i++) {
        	$password = $this->getRandomString(25);

        	$Hash = $this->Perzeus->createHash($password);
        	$valid = $this->Perzeus->validatePassword($password."-", $Hash->hash, $Hash->rand);
            $this->assertFalse($valid);
        }
    }

    protected function getRandomString($length = 8)
    {
		$characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_)*!";
		$string = "";
		for ($i = 0; $i < $length; $i++) {
			$string .= $characters[mt_rand(0, strlen($characters) - 1)];
		}

		return $string;
	}
}
