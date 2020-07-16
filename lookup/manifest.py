from stacker.lookups.handlers import LookupHandler
import semver
import yaml
import logging

class VersionLookup(LookupHandler):
  @classmethod
  def handle(cls, value, **kwargs):
    logging.debug(f"Looking up version for {value}")

    with open("manifest.yaml", "r") as f:
      manifest = yaml.safe_load(f)

    if "::" in value:
      (artifact, part) = value.split("::")
      raw_ver = manifest['versions'][artifact]
      ver = semver.VersionInfo.parse(raw_ver)
    
      if part == "major":
        return str(ver.major)
      elif part == "minor":
        return str(ver.minor)
      elif part == "patch":
        return str(ver.patch)
      elif part == "prerelease":
        return str(ver.prerelease)
      elif part == "build":
        return str(ver.build)
      else:
        raise ValueError(f"Invalid semver part '{part}' - should be one of 'major','minor','patch','prerelease','build'")
    else:
      return manifest['versions'][value]
