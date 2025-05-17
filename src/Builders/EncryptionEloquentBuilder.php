<?php

/**
 * src/Builders/EncryptionEloquentBuilder.php.
 *
 */

namespace ShreeSoftech\DBEncryption\Builders;

use Illuminate\Database\Eloquent\Builder;

class EncryptionEloquentBuilder extends Builder
{
    public function whereEncrypted($param1, $param2, $param3 = null)
    {
        $filter            = new \stdClass();
        $filter->field     = $param1;
        $filter->operation = isset($param3) ? $param2 : '=';
        $filter->value     = isset($param3) ? $param3 : $param2;

        $salt = substr(hash('sha256', config('laravelDatabaseEncryption.encrypt_key')), 0, 16);

        return self::whereRaw("CONVERT(AES_DECRYPT(FROM_BASE64(`{$filter->field}`), '{$salt}') USING utf8mb4) {$filter->operation} ? ", [$filter->value]);
    }

    public function orWhereEncrypted($param1, $param2, $param3 = null)
    {
        $filter            = new \stdClass();
        $filter->field     = $param1;
        $filter->operation = isset($param3) ? $param2 : '=';
        $filter->value     = isset($param3) ? $param3 : $param2;

        $salt = substr(hash('sha256', config('laravelDatabaseEncryption.encrypt_key')), 0, 16);

        return self::orWhereRaw("CONVERT(AES_DECRYPT(FROM_BASE64(`{$filter->field}`), '{$salt}') USING utf8mb4) {$filter->operation} ? ", [$filter->value]);
    }

    public function whereEncryptedAll(array $fields, $operation, $value)
    {
        $query = $this;

        foreach ($fields as $field) {
            $salt = substr(hash('sha256', config('laravelDatabaseEncryption.encrypt_key')), 0, 16);
            $query = $query->whereRaw("CONVERT(AES_DECRYPT(FROM_BASE64(`{$field}`), '{$salt}') USING utf8mb4) {$operation} ?", [$value]);
        }

        return $query;
    }


    public function whereEncryptedAny(array $fields, $operation, $value)
    {
        $query = $this;

        foreach ($fields as $index => $field) {
            $salt = substr(hash('sha256', config('laravelDatabaseEncryption.encrypt_key')), 0, 16);
            if ($index == 0) {
                $query = $query->whereRaw("CONVERT(AES_DECRYPT(FROM_BASE64(`{$field}`), '{$salt}') USING utf8mb4) {$operation} ?", [$value]);
            } else {
                $query = $query->orWhereRaw("CONVERT(AES_DECRYPT(FROM_BASE64(`{$field}`), '{$salt}') USING utf8mb4) {$operation} ?", [$value]);
            }
        }

        return $query;
    }

     /**
     * Order by an encrypted field
     * 
     * @param string $field The encrypted field to order by
     * @param string $direction The direction to order by (asc or desc)
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function orderByEncrypted($field, $direction = 'asc')
    {
        $salt = $this->getEncryptionSalt();

        return self::orderByRaw(
            "CONVERT(AES_DECRYPT(FROM_BASE64(`{$field}`), '{$salt}') USING utf8mb4) {$direction}"
        );
    }
}
