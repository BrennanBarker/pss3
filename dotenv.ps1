get-content .env | ForEach-Object {
    $name, $value = $_.split('=')
    set-content env:\$name $value
}