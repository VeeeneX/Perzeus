<?php
namespace VeeeneX;

ini_set("max_execution_time", 0);

class Perzeus
{
	public $options = [
		"cost" => 11,
        "salt" => "DSASD"
	];
	public $startingSalt;
	public $predendSalt;

	public $min;
	public $max;
	public $avalon;

	public $rand;
	public $predend;

    public function __construct(
        string $startingSalt = null,
        string $salt = null,
        string $endingSalt = null,
        int $min = null,
        int $max = null,
        int $avalon = null
    ) {
        if ($startingSalt === null) {
            $startingSalt = $this->getRandomString(mt_rand(22, 50));
        }
        $this->startingSalt = $startingSalt;

        if ($salt === null) {
            $salt = $this->createSalt();
        }
        $this->options["salt"] = $startingSalt;

        if ($endingSalt === null) {
            $endingSalt = $this->getRandomString(mt_rand(22, 50));
        }
        $this->endingSalt = $endingSalt;

        if ($min === null) {
            $min = mt_rand(0, 50);
        }
        $this->min = $min;

        if ($max === null) {
            $max = mt_rand(50, 100);
        }
        $this->max = $max;

        if ($avalon === null) {
            $avalon = mt_rand(0, 100);
        }
        $this->avalon = $avalon;
    }

	public function createHash($password)
    {
		$rand = rand($this->min, $this->max);
        return (object) [
            "hash" => $this->hashPredend($password, $rand).password_hash($this->predend.$password, PASSWORD_BCRYPT, $this->options),
            "rand" => $rand
        ];
	}

	public function createSalt()
    {
		return $this->startingSalt.bin2hex(openssl_random_pseudo_bytes(22));
	}

	public function hashPredend($password, $rand)
    {
		$randT = ceil(strlen($password)-(abs(strlen($password)/($rand * $this->avalon))*100));
		$this->predend = substr($password, 0, $randT);

		return $this->getRandomString($rand).md5($this->predend.$this->endingSalt);
	}

	public function validatePassword($password, $hash, $rand)
    {
		$d = substr($hash, 0, $rand+32);
		$hardCheck = substr(substr($hash, $rand), 0, 32);

		$randt = ceil(strlen($password)-(abs(strlen($password)/($rand * $this->avalon))*100));
		$predend = substr($password, 0, $randt);

		$hash = ltrim($hash, $d);

		if (password_verify($predend.$password, $hash) && md5($predend.$this->endingSalt) === $hardCheck) {
			return true;
		} else {
			return false;
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
