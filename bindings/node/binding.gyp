{
  "targets": [
    {
      "target_name": "wilis_napi",
      "sources": [ "wilis_napi.c" ],
      "include_dirs": [ "../../include" ],
      "conditions": [
        ["OS=='linux'", {
          "libraries": [
            "-L<(module_root_dir)/../../target/release",
            "-lwilis",
            "-Wl,-rpath,<(module_root_dir)/../../target/release"
          ]
        }],
        ["OS=='mac'", {
          "libraries": [
            "-L<(module_root_dir)/../../target/release",
            "-lwilis",
            "-Wl,-rpath,<(module_root_dir)/../../target/release"
          ]
        }],
        ["OS=='win'", {
          "libraries": [
            "<(module_root_dir)/../../target/release/wilis.dll.lib"
          ]
        }]
      ]
    }
  ]
}
